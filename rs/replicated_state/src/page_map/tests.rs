use super::{
    Buffer, FileDescriptor, MemoryInstructions, MemoryMapOrData, PageAllocatorRegistry, PageIndex,
    PageMap, PageMapSerialization, Shard, StorageMetrics, TestPageAllocatorFileDescriptorImpl,
    checkpoint::Checkpoint,
    page_allocator::PageAllocatorSerialization,
    storage::BaseFileSerialization,
    storage::StorageLayout,
    test_utils::{ShardedTestStorageLayout, base_only_storage_layout},
};
use ic_config::state_manager::LsmtConfig;
use ic_metrics::MetricsRegistry;
use ic_sys::PAGE_SIZE;
use ic_types::{Height, MAX_STABLE_MEMORY_IN_BYTES};
use nix::unistd::dup;
use std::sync::Arc;
use tempfile::{Builder, TempDir};

fn assert_equal_page_maps(page_map1: &PageMap, page_map2: &PageMap) {
    assert_eq!(page_map1.num_host_pages(), page_map2.num_host_pages());
    for i in 0..page_map1.num_host_pages() {
        assert_eq!(
            page_map1.get_page(PageIndex::new(i as u64)),
            page_map2.get_page(PageIndex::new(i as u64))
        );
    }
}

// Since tests run in the same process, we need to duplicate all file
// descriptors so that both page maps can close them.
fn duplicate_file_descriptors(
    mut serialized_page_map: PageMapSerialization,
) -> PageMapSerialization {
    match serialized_page_map.storage.base {
        BaseFileSerialization::Base(ref mut base) => {
            for mapping in base.mapping.iter_mut() {
                mapping.file_descriptor = FileDescriptor {
                    fd: dup(mapping.file_descriptor.fd).unwrap(),
                };
            }
        }
        BaseFileSerialization::Overlay(ref mut overlays) => {
            for ref mut overlay in overlays.iter_mut() {
                overlay.mapping.file_descriptor = FileDescriptor {
                    fd: dup(overlay.mapping.file_descriptor.fd).unwrap(),
                }
            }
        }
    }
    for overlay in serialized_page_map.storage.overlays.iter_mut() {
        overlay.mapping.file_descriptor = FileDescriptor {
            fd: dup(overlay.mapping.file_descriptor.fd).unwrap(),
        };
    }

    serialized_page_map.page_allocator = PageAllocatorSerialization {
        id: serialized_page_map.page_allocator.id,
        fd: FileDescriptor {
            fd: dup(serialized_page_map.page_allocator.fd.fd).unwrap(),
        },
    };
    serialized_page_map
}

#[test]
fn can_debug_display_a_page_map() {
    let page_map = PageMap::new_for_testing();
    assert_eq!(format!("{page_map:?}"), "{}");
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
    let page_map = PageMap::new_for_testing();
    let page = page_map.get_page(PageIndex::new(1));
    assert_eq!(page.len(), PAGE_SIZE);
    assert!(page.iter().all(|b| *b == 0));
}

#[test]
fn can_update_a_page_map() {
    let mut page_map = PageMap::new_for_testing();
    let ones = [1u8; PAGE_SIZE];
    let twos = [2u8; PAGE_SIZE];

    let delta = [(PageIndex::new(1), &ones), (PageIndex::new(2), &twos)];

    page_map.update(&delta);

    for (num, contents) in &[(1, 1), (2, 2), (3, 0)] {
        assert!(
            page_map
                .get_page(PageIndex::new(*num))
                .iter()
                .all(|b| *b == *contents)
        );
    }
}

#[test]
fn new_delta_wins_on_update() {
    let mut page_map = PageMap::new_for_testing();
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
    fn persist_check_eq_and_load(
        pagemap: &mut PageMap,
        pages_to_update: &[(PageIndex, [u8; PAGE_SIZE])],
        metrics: &StorageMetrics,
        height: Height,
        tmp: &TempDir,
    ) -> PageMap {
        pagemap.update(
            &pages_to_update
                .iter()
                .map(|(idx, p)| (*idx, p))
                .collect::<Vec<_>>(),
        );
        let storage_layout = ShardedTestStorageLayout {
            dir_path: tmp.path().to_path_buf(),
            base: tmp.path().join("vmemory_0.bin"),
            overlay_suffix: "vmemory_0.overlay".into(),
        };
        pagemap
            .persist_delta(
                &storage_layout,
                height,
                &LsmtConfig {
                    shard_num_pages: u64::MAX,
                },
                metrics,
            )
            .unwrap();
        let persisted_map = PageMap::open(
            Box::new(storage_layout),
            height,
            Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        )
        .unwrap();

        assert_eq!(*pagemap, persisted_map);
        persisted_map
    }

    let tmp = tempfile::Builder::new()
        .prefix("checkpoints")
        .tempdir()
        .unwrap();

    let base_page = [42u8; PAGE_SIZE];
    let base_data = vec![&base_page; 50];
    let metrics = StorageMetrics::new(&MetricsRegistry::new());
    let mut pagemap = persist_check_eq_and_load(
        &mut PageMap::new_for_testing(),
        &base_data
            .iter()
            .enumerate()
            .map(|(i, page)| (PageIndex::new(i as u64), **page))
            .collect::<Vec<_>>(),
        &metrics,
        Height::new(0),
        &tmp,
    );

    let mut pagemap = persist_check_eq_and_load(
        &mut pagemap,
        &[
            (PageIndex::new(1), [1u8; PAGE_SIZE]),
            (PageIndex::new(3), [3u8; PAGE_SIZE]),
            (PageIndex::new(4), [4u8; PAGE_SIZE]),
            (PageIndex::new(60), [60u8; PAGE_SIZE]),
            (PageIndex::new(63), [63u8; PAGE_SIZE]),
            (PageIndex::new(100), [100u8; PAGE_SIZE]),
        ],
        &metrics,
        Height::new(1),
        &tmp,
    );

    let mut pagemap = persist_check_eq_and_load(
        &mut pagemap,
        &[(PageIndex::new(1), [255u8; PAGE_SIZE])],
        &metrics,
        Height::new(2),
        &tmp,
    );
    // Check that it's possible to serialize without reloading.
    persist_check_eq_and_load(
        &mut pagemap,
        &[(PageIndex::new(104), [104u8; PAGE_SIZE])],
        &metrics,
        Height::new(3),
        &tmp,
    );
    let pagemap = persist_check_eq_and_load(
        &mut pagemap,
        &[(PageIndex::new(103), [103u8; PAGE_SIZE])],
        &metrics,
        Height::new(4),
        &tmp,
    );
    assert_eq!(105, pagemap.num_host_pages());
}

#[test]
fn can_persist_and_load_an_empty_page_map() {
    let tmp = tempfile::Builder::new()
        .prefix("checkpoints")
        .tempdir()
        .unwrap();
    let original_map = PageMap::new_for_testing();
    let metrics = StorageMetrics::new(&MetricsRegistry::new());
    let storage_layout = ShardedTestStorageLayout {
        dir_path: tmp.path().to_path_buf(),
        base: tmp.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".into(),
    };
    original_map
        .persist_delta(
            &storage_layout,
            Height::new(0),
            &LsmtConfig {
                shard_num_pages: u64::MAX,
            },
            &metrics,
        )
        .unwrap();
    let persisted_map = PageMap::open(
        Box::new(storage_layout),
        Height::new(0),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .expect("opening an empty page map must succeed");

    // base_height will be different, but is not part of eq
    assert_eq!(original_map, persisted_map);
}

#[test]
fn can_load_a_page_map_without_files() {
    let tmp = tempfile::Builder::new()
        .prefix("checkpoints")
        .tempdir()
        .unwrap();
    let heap_file = tmp.path().join("missing_file");

    let loaded_map = PageMap::open(
        Box::new(base_only_storage_layout(heap_file.to_path_buf())),
        Height::new(0),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .expect("opening an empty page map must succeed");

    // base_height will be different, but is not part of eq
    assert_eq!(PageMap::new_for_testing(), loaded_map);
}

#[test]
fn can_use_buffer_to_modify_page_map() {
    let page_1 = [1u8; PAGE_SIZE];
    let page_3 = [3u8; PAGE_SIZE];
    let pages = &[(PageIndex::new(1), &page_1), (PageIndex::new(3), &page_3)];
    let mut page_map = PageMap::new_for_testing();
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
    let page_allocator_registry = PageAllocatorRegistry::new();
    let original_page_map = PageMap::new_for_testing();
    let serialized_page_map = duplicate_file_descriptors(original_page_map.serialize());
    let deserialized_page_map =
        PageMap::deserialize(serialized_page_map, &page_allocator_registry).unwrap();
    assert_equal_page_maps(&original_page_map, &deserialized_page_map);
}

#[test]
fn serialize_page_map() {
    let page_allocator_registry = PageAllocatorRegistry::new();
    let mut replica = PageMap::new_for_testing();
    // The replica process sends the page map to the sandbox process.
    let serialized_page_map = duplicate_file_descriptors(replica.serialize());
    let mut sandbox = PageMap::deserialize(serialized_page_map, &page_allocator_registry).unwrap();
    // The sandbox process allocates new pages.
    let page_1 = [1u8; PAGE_SIZE];
    let page_3 = [3u8; PAGE_SIZE];
    let page_7 = [7u8; PAGE_SIZE];
    let pages = &[(PageIndex::new(1), &page_1), (PageIndex::new(3), &page_3)];
    sandbox.update(pages);
    sandbox.strip_unflushed_delta();
    sandbox.update(&[(PageIndex::new(7), &page_7)]);
    // The sandbox process sends the dirty pages to the replica process.
    let page_delta =
        sandbox.serialize_delta(&[PageIndex::new(1), PageIndex::new(3), PageIndex::new(7)]);
    replica.deserialize_delta(page_delta);
    // The page deltas must be in sync.
    assert_equal_page_maps(&replica, &sandbox);
}

/// Check that the value provided by `calculate_dirty_pages` agrees with the
/// actual change in number of dirty pages and return the number of new dirty
/// pages.
fn write_and_verify_dirty_pages(buf: &mut Buffer, src: &[u8], offset: usize) -> u64 {
    let new = buf.dirty_pages_from_write(offset as u64, src.len() as u64);
    let initial = buf.dirty_pages().len();
    buf.write(src, offset);
    let updated = buf.dirty_pages().len();
    assert_eq!(updated - initial, new.get() as usize);
    new.get()
}

/// Complete re-write of first page is dirty, later write doesn't increase
/// count.
#[test]
fn buffer_entire_first_page_write() {
    let mut buf = Buffer::new(PageMap::new_for_testing());
    assert_eq!(
        1,
        write_and_verify_dirty_pages(&mut buf, &[0; PAGE_SIZE], 0)
    );
    assert_eq!(0, write_and_verify_dirty_pages(&mut buf, &[0; 1], 0));
}

/// Single write to first page is dirty, later write doesn't increase count.
#[test]
fn buffer_single_byte_first_page_write() {
    let mut buf = Buffer::new(PageMap::new_for_testing());
    assert_eq!(1, write_and_verify_dirty_pages(&mut buf, &[0; 1], 0));
    assert_eq!(0, write_and_verify_dirty_pages(&mut buf, &[0; 1], 1));
}

#[test]
fn buffer_write_single_byte_each_page() {
    let mut buf = Buffer::new(PageMap::new_for_testing());
    assert_eq!(1, write_and_verify_dirty_pages(&mut buf, &[0; 1], 0));
    assert_eq!(
        1,
        write_and_verify_dirty_pages(&mut buf, &[0; 1], PAGE_SIZE)
    );
    assert_eq!(
        1,
        write_and_verify_dirty_pages(&mut buf, &[0; 1], 2 * PAGE_SIZE)
    );
    assert_eq!(
        1,
        write_and_verify_dirty_pages(&mut buf, &[0; 1], 15 * PAGE_SIZE)
    );
}

#[test]
fn buffer_write_unaligned_multiple_pages() {
    const NUM_PAGES: u64 = 3;
    let mut buf = Buffer::new(PageMap::new_for_testing());
    assert_eq!(
        NUM_PAGES + 1,
        write_and_verify_dirty_pages(&mut buf, &[0; (NUM_PAGES as usize) * PAGE_SIZE], 24)
    );
}

#[test]
fn buffer_write_empty_slice() {
    let mut buf = Buffer::new(PageMap::new_for_testing());
    assert_eq!(0, write_and_verify_dirty_pages(&mut buf, &[0; 0], 10_000));
}

// Checks that the pre-computed dirty pages agrees with the difference in dirty
// pages from before and after a write.
#[test]
fn calc_dirty_pages_matches_actual_change() {
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    runner
        .run(
            &(0..MAX_STABLE_MEMORY_IN_BYTES, 0..(1000 * PAGE_SIZE as u64)),
            |(offset, size)| {
                // bound size to valid range
                let size = (MAX_STABLE_MEMORY_IN_BYTES - offset).min(size);
                let src = vec![0; size as usize];
                // Start with a buffer that has some initial dirty pages
                let mut buffer = Buffer::new(PageMap::new_for_testing());
                buffer.write(&[1; 10 * PAGE_SIZE], 5 * PAGE_SIZE + 10);
                buffer.write(&[3; 16], 44 * PAGE_SIZE);

                write_and_verify_dirty_pages(&mut buffer, &src, offset as usize);
                Ok(())
            },
        )
        .unwrap()
}

#[test]
fn get_memory_instructions_returns_deltas() {
    let mut page_map = PageMap::new_for_testing();
    let tmp = tempfile::Builder::new()
        .prefix("checkpoints")
        .tempdir()
        .unwrap();
    let pages = &[(PageIndex::new(1), &[1u8; PAGE_SIZE])];
    page_map.update(pages);

    assert_eq!(
        MemoryInstructions {
            range: PageIndex::new(0)..PageIndex::new(u64::MAX),
            instructions: vec![]
        },
        page_map.get_base_memory_instructions()
    );
    let range = PageIndex::new(0)..PageIndex::new(10);
    assert_eq!(
        MemoryInstructions {
            range: range.clone(),
            instructions: vec![(
                PageIndex::new(1)..PageIndex::new(2),
                MemoryMapOrData::Data(&[1u8; PAGE_SIZE])
            )]
        },
        page_map.get_memory_instructions(range.clone(), range.clone())
    );
    let metrics = StorageMetrics::new(&MetricsRegistry::new());
    let storage_layout = ShardedTestStorageLayout {
        dir_path: tmp.path().to_path_buf(),
        base: tmp.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".into(),
    };
    page_map
        .persist_delta(
            &storage_layout,
            Height::new(0),
            &LsmtConfig {
                shard_num_pages: u64::MAX,
            },
            &metrics,
        )
        .unwrap();

    let mut page_map = PageMap::open(
        Box::new(storage_layout),
        Height::new(0),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .unwrap();

    assert!(matches!(
        page_map.get_base_memory_instructions().instructions[..],
        [(ref range, _)] if *range == (PageIndex::new(1)..PageIndex::new(2))
    ));
    assert_eq!(
        MemoryInstructions {
            range: range.clone(),
            instructions: vec![]
        },
        page_map.get_memory_instructions(range.clone(), range.clone())
    );

    let pages = &[
        (PageIndex::new(3), &[1u8; PAGE_SIZE]),
        (PageIndex::new(5), &[1u8; PAGE_SIZE]),
        (PageIndex::new(20), &[1u8; PAGE_SIZE]),
    ];
    page_map.update(pages);

    assert!(matches!(
        page_map.get_base_memory_instructions().instructions[..],
        [(ref range, _)] if *range == (PageIndex::new(1)..PageIndex::new(2))
    ));
    assert_eq!(
        MemoryInstructions {
            range: range.clone(),
            instructions: vec![
                (
                    PageIndex::new(3)..PageIndex::new(4),
                    MemoryMapOrData::Data(&[1u8; PAGE_SIZE])
                ),
                (
                    PageIndex::new(5)..PageIndex::new(6),
                    MemoryMapOrData::Data(&[1u8; PAGE_SIZE])
                )
            ]
        },
        page_map.get_memory_instructions(range.clone(), range)
    );
}

#[test]
fn get_memory_instructions_respects_min_range() {
    let mut page_map = PageMap::new_for_testing();
    let pages: Vec<_> = (10..20)
        .map(|i| (PageIndex::new(i), &[1u8; PAGE_SIZE]))
        .collect();
    page_map.update(&pages);

    assert_eq!(
        PageIndex::new(12)..PageIndex::new(17),
        page_map
            .get_memory_instructions(
                PageIndex::new(12)..PageIndex::new(17),
                PageIndex::new(0)..PageIndex::new(30),
            )
            .range
    );
}

#[test]
fn get_memory_instructions_returns_max_range_on_empty_map() {
    let page_map = PageMap::new_for_testing();

    assert_eq!(
        PageIndex::new(0)..PageIndex::new(30),
        page_map
            .get_memory_instructions(
                PageIndex::new(12)..PageIndex::new(17),
                PageIndex::new(0)..PageIndex::new(30),
            )
            .range
    );

    assert_eq!(
        PageIndex::new(0)..PageIndex::new(30),
        page_map
            .get_memory_instructions(
                PageIndex::new(12)..PageIndex::new(17),
                PageIndex::new(0)..PageIndex::new(30),
            )
            .range
    );
}

#[test]
fn get_memory_instructions_grows_left_and_right() {
    let mut page_map = PageMap::new_for_testing();
    let pages: Vec<_> = (10..20)
        .map(|i| (PageIndex::new(i), &[1u8; PAGE_SIZE]))
        .collect();
    page_map.update(&pages);
    let pages = &[
        (PageIndex::new(5), &[1u8; PAGE_SIZE]),
        (PageIndex::new(35), &[1u8; PAGE_SIZE]),
    ];
    page_map.update(pages);

    assert_eq!(
        // Just to the edge of the page deltas at 5 and 35.
        PageIndex::new(6)..PageIndex::new(35),
        page_map
            .get_memory_instructions(
                PageIndex::new(7)..PageIndex::new(20),
                PageIndex::new(0)..PageIndex::new(40),
            )
            .range
    );
}

#[test]
fn get_memory_instructions_ignores_base_file() {
    let metrics = StorageMetrics::new(&MetricsRegistry::new());
    let lsmt_config = LsmtConfig {
        shard_num_pages: u64::MAX,
    };
    let tempdir = Builder::new().prefix("page_map_test").tempdir().unwrap();
    let storage_layout = ShardedTestStorageLayout {
        dir_path: tempdir.path().to_path_buf(),
        base: tempdir.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".into(),
    };

    let mut page_map = PageMap::new_for_testing();
    // Consecutive pages, so that they get treated like a base file.
    let pages: Vec<_> = (10..20)
        .map(|i| (PageIndex::new(i), &[1u8; PAGE_SIZE]))
        .collect();
    page_map.update(&pages);
    page_map
        .persist_unflushed_delta(&storage_layout, Height::new(0), &lsmt_config, &metrics)
        .unwrap();

    assert!(!storage_layout.base().exists());
    assert!(
        storage_layout
            .overlay(Height::new(0), Shard::new(0))
            .exists()
    );

    let page_map = PageMap::open(
        Box::new(storage_layout),
        Height::new(0),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .unwrap();

    let base_instructions = page_map.get_base_memory_instructions();
    assert_eq!(base_instructions.instructions.len(), 1);
    assert_eq!(
        base_instructions.instructions.first().unwrap().0,
        PageIndex::new(10)..PageIndex::new(20)
    );

    let range = PageIndex::new(0)..PageIndex::new(100);
    let memory_instructions = page_map.get_memory_instructions(range.clone(), range.clone());
    // No non-base overlays or page deltas, so no instructions to report.
    assert_eq!(memory_instructions.range, range);
    assert_eq!(memory_instructions.instructions.len(), 0);
}

#[test]
fn get_memory_instructions_stops_at_instructions_outside_min_range() {
    let metrics = StorageMetrics::new(&MetricsRegistry::new());
    let lsmt_config = LsmtConfig {
        shard_num_pages: u64::MAX,
    };
    let tempdir = Builder::new().prefix("page_map_test").tempdir().unwrap();
    let storage_layout = ShardedTestStorageLayout {
        dir_path: tempdir.path().to_path_buf(),
        base: tempdir.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".into(),
    };

    let mut page_map = PageMap::new_for_testing();
    // Consecutive pages, so that they get treated like a base file.
    let pages: Vec<_> = (10..20)
        .map(|i| (PageIndex::new(i), &[1u8; PAGE_SIZE]))
        .collect();
    page_map.update(&pages);
    page_map
        .persist_unflushed_delta(&storage_layout, Height::new(0), &lsmt_config, &metrics)
        .unwrap();
    page_map.strip_unflushed_delta();

    let pages = vec![
        (PageIndex::new(5), &[1u8; PAGE_SIZE]),
        (PageIndex::new(35), &[1u8; PAGE_SIZE]),
    ];
    page_map.update(&pages);
    page_map
        .persist_unflushed_delta(&storage_layout, Height::new(1), &lsmt_config, &metrics)
        .unwrap();

    assert!(!storage_layout.base().exists());
    assert!(
        storage_layout
            .overlay(Height::new(0), Shard::new(0))
            .exists()
    );
    assert!(
        storage_layout
            .overlay(Height::new(1), Shard::new(0))
            .exists()
    );

    let page_map = PageMap::open(
        Box::new(storage_layout),
        Height::new(1),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .unwrap();

    let memory_instructions = page_map.get_memory_instructions(
        PageIndex::new(15)..PageIndex::new(20),
        PageIndex::new(0)..PageIndex::new(100),
    );
    // The two papes in overlays are outside of min_range, but inside max_range
    assert_eq!(
        memory_instructions.range,
        PageIndex::new(6)..PageIndex::new(35)
    );
    assert_eq!(memory_instructions.instructions.len(), 0);

    let memory_instructions = page_map.get_memory_instructions(
        PageIndex::new(2)..PageIndex::new(40),
        PageIndex::new(0)..PageIndex::new(100),
    );
    // The only two papes in overlays are inside min_range, so we extend all the way to max_range.
    assert_eq!(
        memory_instructions.range,
        PageIndex::new(0)..PageIndex::new(100)
    );
    assert_eq!(memory_instructions.instructions.len(), 2);
}

#[test]
fn get_memory_instructions_extends_mmap_past_min_range() {
    let metrics = StorageMetrics::new(&MetricsRegistry::new());
    let lsmt_config = LsmtConfig {
        shard_num_pages: u64::MAX,
    };
    let tempdir = Builder::new().prefix("page_map_test").tempdir().unwrap();
    let storage_layout = ShardedTestStorageLayout {
        dir_path: tempdir.path().to_path_buf(),
        base: tempdir.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".into(),
    };

    let mut page_map = PageMap::new_for_testing();
    // Consecutive pages, so that they get treated like a base file.
    let pages: Vec<_> = (10..20)
        .map(|i| (PageIndex::new(i), &[1u8; PAGE_SIZE]))
        .collect();
    page_map.update(&pages);
    page_map
        .persist_unflushed_delta(&storage_layout, Height::new(0), &lsmt_config, &metrics)
        .unwrap();
    page_map.strip_unflushed_delta();

    let pages: Vec<_> = (15..40)
        .map(|i| (PageIndex::new(i), &[1u8; PAGE_SIZE]))
        .collect();
    page_map.update(&pages);
    page_map
        .persist_unflushed_delta(&storage_layout, Height::new(1), &lsmt_config, &metrics)
        .unwrap();

    assert!(!storage_layout.base().exists());
    assert!(
        storage_layout
            .overlay(Height::new(0), Shard::new(0))
            .exists()
    );
    assert!(
        storage_layout
            .overlay(Height::new(1), Shard::new(0))
            .exists()
    );

    let page_map = PageMap::open(
        Box::new(storage_layout),
        Height::new(1),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .unwrap();

    let memory_instructions = page_map.get_memory_instructions(
        PageIndex::new(10)..PageIndex::new(20),
        PageIndex::new(0)..PageIndex::new(100),
    );
    // The large range in the overlay is only partially within min_range, but it is extended as it doesn't require extra instructions.
    assert_eq!(
        memory_instructions.range,
        PageIndex::new(0)..PageIndex::new(100)
    );
    assert_eq!(memory_instructions.instructions.len(), 1);
    assert_eq!(
        memory_instructions.instructions.first().unwrap().0,
        PageIndex::new(15)..PageIndex::new(40)
    );

    let memory_instructions = page_map.get_memory_instructions(
        PageIndex::new(20)..PageIndex::new(50),
        PageIndex::new(0)..PageIndex::new(100),
    );
    // The large range in the overlay is only partially within min_range, but it is extended as it doesn't require extra instructions.
    assert_eq!(
        memory_instructions.range,
        PageIndex::new(0)..PageIndex::new(100)
    );
    assert_eq!(memory_instructions.instructions.len(), 1);
    assert_eq!(
        memory_instructions.instructions.first().unwrap().0,
        PageIndex::new(15)..PageIndex::new(40)
    );
}

#[test]
fn restrict_to_range() {
    let small_data = [1_u8; PAGE_SIZE];
    let mut large_data = vec![2_u8; PAGE_SIZE];
    large_data.extend_from_slice(&[3_u8; PAGE_SIZE]);
    let fd = FileDescriptor { fd: 0 };

    let instructions = vec![
        // Will get dropped.
        (
            PageIndex::new(0)..PageIndex::new(1),
            MemoryMapOrData::Data(&small_data),
        ),
        // Will get left part cut off.
        (
            PageIndex::new(5)..PageIndex::new(15),
            MemoryMapOrData::MemoryMap(fd.clone(), 5 * PAGE_SIZE),
        ),
        // Will get left part cut off.
        (
            PageIndex::new(9)..PageIndex::new(11),
            MemoryMapOrData::Data(&large_data),
        ),
        // Will be preserved.
        (
            PageIndex::new(10)..PageIndex::new(12),
            MemoryMapOrData::MemoryMap(fd.clone(), 10 * PAGE_SIZE),
        ),
        // Will get right part cut off.
        (
            PageIndex::new(15)..PageIndex::new(25),
            MemoryMapOrData::MemoryMap(fd.clone(), 15 * PAGE_SIZE),
        ),
        // Will get right part cut off.
        (
            PageIndex::new(19)..PageIndex::new(21),
            MemoryMapOrData::Data(&large_data),
        ),
        // Will get parts cut off from both sides
        (
            PageIndex::new(5)..PageIndex::new(25),
            MemoryMapOrData::MemoryMap(fd.clone(), 20 * PAGE_SIZE),
        ),
        // Will get dropped.
        (
            PageIndex::new(25)..PageIndex::new(30),
            MemoryMapOrData::MemoryMap(fd.clone(), 25 * PAGE_SIZE),
        ),
    ];

    let mut memory_instructions = MemoryInstructions {
        range: PageIndex::new(0)..PageIndex::new(100),
        instructions,
    };

    memory_instructions.restrict_to_range(&(PageIndex::new(10)..PageIndex::new(20)));

    let expected_instructions = vec![
        (
            PageIndex::new(10)..PageIndex::new(15),
            MemoryMapOrData::MemoryMap(fd.clone(), (5 + 5) * PAGE_SIZE),
        ),
        (
            PageIndex::new(10)..PageIndex::new(11),
            MemoryMapOrData::Data(&large_data[PAGE_SIZE..]),
        ),
        (
            PageIndex::new(10)..PageIndex::new(12),
            MemoryMapOrData::MemoryMap(fd.clone(), 10 * PAGE_SIZE),
        ),
        (
            PageIndex::new(15)..PageIndex::new(20),
            MemoryMapOrData::MemoryMap(fd.clone(), 15 * PAGE_SIZE),
        ),
        (
            PageIndex::new(19)..PageIndex::new(20),
            MemoryMapOrData::Data(&large_data[..PAGE_SIZE]),
        ),
        (
            PageIndex::new(10)..PageIndex::new(20),
            MemoryMapOrData::MemoryMap(fd.clone(), (20 + 5) * PAGE_SIZE),
        ),
    ];

    let expected_memory_instructions = MemoryInstructions {
        range: PageIndex::new(10)..PageIndex::new(20),
        instructions: expected_instructions,
    };

    assert_eq!(memory_instructions, expected_memory_instructions);
}
