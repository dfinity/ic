use std::{
    fs::File,
    io::Write,
    os::{fd::FromRawFd, unix::prelude::FileExt},
    path::{Path, PathBuf},
};

use crate::page_map::{
    storage::{
        Checkpoint, MergeCandidate, OverlayFile, Storage, CURRENT_OVERLAY_VERSION,
        PAGE_INDEX_RANGE_NUM_BYTES, SIZE_NUM_BYTES, VERSION_NUM_BYTES,
    },
    FileDescriptor, MemoryInstructions, MemoryMapOrData, PageAllocator, PageDelta, PageMap,
    PersistDestination, PersistenceError, StorageLayout, StorageMetrics, MAX_NUMBER_OF_FILES,
};
use assert_matches::assert_matches;
use bit_vec::BitVec;
use ic_metrics::MetricsRegistry;
use ic_sys::{PageIndex, PAGE_SIZE};
use ic_test_utilities::io::{make_mutable, make_readonly, write_all_at};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::Height;
use tempfile::{tempdir, TempDir};

struct TestStorageLayout {
    base: PathBuf,
    overlay_dst: PathBuf,
    existing_overlays: Vec<PathBuf>,
}

impl StorageLayout for TestStorageLayout {
    fn base(&self) -> PathBuf {
        self.base.clone()
    }
    fn overlay(&self, _height: Height) -> PathBuf {
        self.overlay_dst.clone()
    }
    fn existing_overlays(&self) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        Ok(self.existing_overlays.clone())
    }
}

/// The expected size of an overlay file.
///
/// The expectation is based on how many pages the overlay contains and how many distinct
/// ranges of indices there are.
fn expected_overlay_file_size(num_pages: u64, num_ranges: u64) -> u64 {
    let data = num_pages * PAGE_SIZE as u64;
    let index = num_ranges * PAGE_INDEX_RANGE_NUM_BYTES as u64;

    data + index + SIZE_NUM_BYTES as u64 + VERSION_NUM_BYTES as u64
}

/// Verify that the overlay file at `path` is internally consistent and contains
/// the same data as `expected`.
fn verify_overlay_file(path: &Path, expected: &PageDelta) {
    // Count the number of separate index ranges.
    let mut num_separate_ranges: u64 = 0;
    let mut last_index = None;
    for (key, _) in expected.iter() {
        let key = key.get();
        if last_index.is_none() || last_index.unwrap() != key - 1 {
            num_separate_ranges += 1;
        }
        last_index = Some(key);
    }

    // Verify the file size is as expected.
    let file_size = path.metadata().unwrap().len();
    assert_eq!(
        expected_overlay_file_size(expected.num_pages() as u64, num_separate_ranges),
        file_size
    );

    let overlay = OverlayFile::load(path).unwrap();

    // Verify `num_pages` and `num_logical_pages`.
    assert_eq!(expected.num_pages(), overlay.num_pages());
    assert_eq!(
        expected.max_page_index().unwrap().get() + 1,
        overlay.num_logical_pages() as u64
    );

    // Verify every single page in the range.
    for index in 0..overlay.num_logical_pages() as u64 {
        let index = PageIndex::new(index);
        assert_eq!(
            overlay.get_page(index),
            expected.get_page(index),
            "Index: {}",
            index
        );
    }

    // `get_page` should return `None` beyond the range of the overlay.
    assert_eq!(
        overlay.get_page(PageIndex::new(overlay.num_logical_pages() as u64)),
        None
    );
    assert_eq!(
        overlay.get_page(PageIndex::new(overlay.num_logical_pages() as u64 + 1)),
        None
    );
}

/// Read all data in input files as PageDelta.
fn files_as_delta(base: &Option<Checkpoint>, overlays: &[OverlayFile]) -> PageDelta {
    let allocator = PageAllocator::new_for_testing();
    let mut pages = Vec::default();
    let num_logical_pages = overlays
        .iter()
        .map(|f| f.num_logical_pages())
        .chain(base.iter().map(|b| b.num_pages()))
        .max()
        .unwrap_or(0);
    for index in 0..num_logical_pages {
        let index = PageIndex::new(index as u64);
        let page = (|| {
            for file in overlays.iter().rev() {
                if let Some(data) = file.get_page(index) {
                    return Some(data);
                }
            }
            base.as_ref().map(|base| base.get_page(index))
        })();
        if let Some(data) = page {
            pages.push((index, data));
        }
    }
    PageDelta::from(allocator.allocate(&pages))
}

/// Check that we have at most MAX_NUMBER_OF_FILES files and they form a pyramid, i.e.
/// each files size is bigger or equal than sum of files on top of it.
fn check_post_merge_criteria(storage_files: &StorageFiles) {
    let file_lengths = storage_files
        .base
        .iter()
        .chain(storage_files.overlays.iter())
        .map(|p| std::fs::metadata(p).unwrap().len())
        .collect::<Vec<_>>();
    assert!(file_lengths.len() <= MAX_NUMBER_OF_FILES);
    file_lengths
        .iter()
        .rev()
        .fold(0, |size_on_top, current_size| {
            assert!(size_on_top <= *current_size);
            size_on_top + current_size
        });
}

/// Verify that the data in `new_base` is the same as in `old_base` + `old_files`.
fn verify_merge_to_base(
    new_base: &Path,
    old_base: Option<Checkpoint>,
    old_overlays: Vec<OverlayFile>,
) {
    let delta = files_as_delta(&old_base, &old_overlays);
    let dst = Checkpoint::open(new_base).unwrap();
    assert_eq!(
        delta.iter().last().unwrap().0.get() + 1,
        dst.num_pages() as u64
    );
    let zeroes = [0; PAGE_SIZE];
    for i in 0..dst.num_pages() as u64 {
        let page_index = PageIndex::new(i);
        match (delta.get_page(page_index), dst.get_page(page_index)) {
            (Some(data_delta), data_dst) => assert_eq!(data_delta, data_dst),
            (None, data_dst) => assert_eq!(&zeroes, data_dst),
        }
    }
}

fn is_none_or_zeroes(pagemap: Option<&[u8; PAGE_SIZE]>) -> bool {
    if let Some(data) = pagemap {
        !data.iter().any(|c| *c != 0)
    } else {
        true
    }
}

/// Verify that the data in `new_overlay` is the same as in `old_base` + `old_files`.
fn verify_merge_to_overlay(
    new_overlay: &Path,
    old_base: Option<Checkpoint>,
    old_overlays: Vec<OverlayFile>,
) {
    let delta = files_as_delta(&old_base, &old_overlays);
    let dst = OverlayFile::load(new_overlay).unwrap();
    assert_eq!(
        delta.iter().last().unwrap().0.get() + 1,
        dst.num_logical_pages() as u64
    );
    for i in 0..dst.num_logical_pages() as u64 {
        let page_index = PageIndex::new(i);
        if delta.get_page(page_index).is_none() {
            assert!(is_none_or_zeroes(dst.get_page(page_index)));
        } else {
            assert_eq!(
                delta.get_page(page_index),
                dst.get_page(page_index),
                "Failed for idx {:#?}",
                page_index
            );
        }
    }
}

/// Write the entire data from `delta` into a byte buffer.
fn page_delta_as_buffer(delta: &PageDelta) -> Vec<u8> {
    let num_pages = if let Some(max) = delta.max_page_index() {
        max.get() as usize + 1
    } else {
        // `delta` is empty in this case.
        0
    };

    let mut result: Vec<u8> = vec![0; num_pages * PAGE_SIZE];
    for (index, data) in delta.iter() {
        let offset = index.get() as usize * PAGE_SIZE;
        unsafe {
            let dst = result.as_mut_ptr().add(offset);
            std::ptr::copy_nonoverlapping(data.contents().as_ptr(), dst, data.contents().len());
        }
    }
    result
}

/// Apply memory instructions to a byte buffer.
/// This is similar to what the `memory_tracker` is doing with these instructions.
fn apply_memory_instructions(instructions: MemoryInstructions, buf: &mut Vec<u8>) {
    let MemoryInstructions {
        range: _,
        instructions,
    } = instructions;
    for (range, mmap_or_data) in instructions {
        let write_offset = range.start.get() as usize * PAGE_SIZE;
        match mmap_or_data {
            MemoryMapOrData::MemoryMap(FileDescriptor { fd }, read_offset) => {
                let write_size = (range.end.get() - range.start.get()) as usize * PAGE_SIZE;
                unsafe {
                    let file = File::from_raw_fd(fd);
                    file.read_exact_at(
                        &mut buf[write_offset..write_offset + write_size],
                        read_offset as u64,
                    )
                    .unwrap();
                    #[allow(clippy::mem_forget)]
                    std::mem::forget(file); // Do not close the file.
                };
            }
            MemoryMapOrData::Data(data) => unsafe {
                let dst = buf.as_mut_ptr().add(write_offset);
                std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len())
            },
        }
    }
}

/// Write the entire data of `storage` into a byte buffer using the `get_memory_instructions` API.
fn storage_as_buffer(storage: &Storage) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0; storage.num_logical_pages() * PAGE_SIZE];
    let full_range = PageIndex::new(0)..PageIndex::new(storage.num_logical_pages() as u64);
    let mut filter = BitVec::from_elem(
        (full_range.end.get() - full_range.start.get()) as usize,
        false,
    );
    apply_memory_instructions(storage.get_base_memory_instructions(), &mut result);
    apply_memory_instructions(
        storage.get_memory_instructions(full_range.clone(), &mut filter),
        &mut result,
    );
    result
}

#[derive(Eq, Clone, Debug, PartialEq)]
struct StorageFiles {
    base: Option<PathBuf>,
    overlays: Vec<PathBuf>,
}

/// Base file and storage file in directory `dir`.
/// These tests use the schema where the base file ends in `.bin`,
/// and overlays end in `.overlay`.
fn storage_files(dir: &Path) -> StorageFiles {
    let mut bases: Vec<PathBuf> = Default::default();
    let mut overlays: Vec<PathBuf> = Default::default();
    for file in std::fs::read_dir(dir).unwrap() {
        let path = file.unwrap().path();
        if path.to_str().unwrap().ends_with("overlay") {
            overlays.push(path);
        } else if path.to_str().unwrap().ends_with("bin") {
            bases.push(path);
        }
    }
    overlays.sort();
    assert!(bases.len() <= 1);

    StorageFiles {
        base: bases.first().cloned(),
        overlays,
    }
}

/// Verify that the storage in the `dir` directory is equivalent to `expected`.
fn verify_storage(dir: &Path, expected: &PageDelta) {
    let StorageFiles { base, overlays } = storage_files(dir);

    let storage = Storage::load(base.as_deref(), &overlays).unwrap();

    let expected_num_pages = if let Some(max) = expected.max_page_index() {
        max.get() + 1
    } else {
        // `delta` is empty in this case.
        0
    };

    // Verify `num_logical_pages`.
    assert_eq!(expected_num_pages, storage.num_logical_pages() as u64);

    // Verify every single page in the range.
    for index in 0..storage.num_logical_pages() as u64 {
        let index = PageIndex::new(index);
        assert_eq!(
            storage.get_page(index),
            expected.get_page(index).unwrap_or(&[0; PAGE_SIZE])
        );
    }

    // `get_page` should return zeroes beyond the range of the storage.
    assert_eq!(
        storage.get_page(PageIndex::new(storage.num_logical_pages() as u64)),
        &[0; PAGE_SIZE]
    );
    assert_eq!(
        storage.get_page(PageIndex::new(storage.num_logical_pages() as u64 + 1)),
        &[0; PAGE_SIZE]
    );

    // Apply pages to a memory region.
    let expected_buffer = page_delta_as_buffer(expected);

    // Apply memory instructions to another memory region.
    let actual_buffer = storage_as_buffer(&storage);

    assert_eq!(expected_buffer, actual_buffer);
}

fn merge_assert_num_files(
    merge_files: usize,
    merge: &Option<MergeCandidate>,
    before: &StorageFiles,
    after: &StorageFiles,
) {
    let before_len = before.overlays.len() + before.base.iter().len();
    let after_len = after.overlays.len() + after.base.iter().len();
    assert_eq!(
        merge
            .as_ref()
            .map_or(0, |m| m.overlays.len() + m.base.iter().len()),
        merge_files
    );
    assert_eq!(before_len - after_len + 1, merge_files);
}

/// An instruction to modify a storage.
#[derive(Debug, Clone)]
enum Instruction {
    /// Create an overlay file with provided list of `PageIndex` to write.
    WriteOverlay(Vec<u64>),
    /// Create & apply `MergeCandidate`; check for amount of files merged.
    Merge {
        is_downgrade: bool,
        assert_files_merged: Option<usize>,
    },
}
use Instruction::*;

/// This function applies `instructions` to a new `Storage` in a temporary directory.
/// At the same time, we apply the same instructions to a `PageDelta`, which acts as the reference
/// implementation. After each operation, we check that all overlay files are as expected and
/// correspond to the reference.
fn write_overlays_and_verify_with_tempdir(
    instructions: Vec<Instruction>,
    tempdir: &TempDir,
) -> MetricsRegistry {
    let allocator = PageAllocator::new_for_testing();
    let metrics_registry = MetricsRegistry::new();
    let metrics = StorageMetrics::new(&metrics_registry);

    let mut combined_delta = PageDelta::default();

    for (round, instruction) in instructions.iter().enumerate() {
        let path_overlay = &tempdir
            .path()
            .join(format!("{:06}_vmemory_0.overlay", round));
        let path_base = &tempdir.path().join("vmemory_0.bin");
        match instruction {
            WriteOverlay(round_indices) => {
                let data = &[round as u8; PAGE_SIZE];
                let overlay_pages: Vec<_> = round_indices
                    .iter()
                    .map(|i| (PageIndex::new(*i), data))
                    .collect();

                let delta = PageDelta::from(allocator.allocate(&overlay_pages));

                OverlayFile::write(&delta, path_overlay, &metrics).unwrap();

                // Check both the file we just wrote and the resulting directory for correctness.
                verify_overlay_file(path_overlay, &delta);

                combined_delta.update(delta);

                verify_storage(tempdir.path(), &combined_delta);
            }

            Merge {
                is_downgrade,
                assert_files_merged,
            } => {
                let files_before = storage_files(tempdir.path());

                let mut page_map = PageMap::new_for_testing();
                page_map.update(
                    combined_delta
                        .iter()
                        .map(|(i, p)| (i, p.contents()))
                        .collect::<Vec<_>>()
                        .as_slice(),
                );

                let merge = if *is_downgrade {
                    MergeCandidate::merge_to_base(&TestStorageLayout {
                        base: path_base.to_path_buf(),
                        overlay_dst: path_overlay.to_path_buf(),
                        existing_overlays: files_before.overlays.clone(),
                    })
                    .unwrap()
                } else {
                    MergeCandidate::new(
                        &TestStorageLayout {
                            base: path_base.to_path_buf(),
                            overlay_dst: path_overlay.to_path_buf(),
                            existing_overlays: files_before.overlays.clone(),
                        },
                        Height::from(0),
                    )
                    .unwrap()
                };
                // Open the files before they might get deleted.
                let merged_overlays: Vec<_> = merge.as_ref().map_or(Vec::new(), |m| {
                    m.overlays
                        .iter()
                        .map(|path| OverlayFile::load(path).unwrap())
                        .collect()
                });
                let merged_base = merge
                    .as_ref()
                    .and_then(|m| m.base.as_ref().map(|path| Checkpoint::open(path).unwrap()));

                if let Some(merge) = merge.as_ref() {
                    merge.apply(&metrics).unwrap();
                }

                let files_after = storage_files(tempdir.path());

                if let Some(assert_files_merged) = assert_files_merged {
                    merge_assert_num_files(
                        *assert_files_merged,
                        &merge,
                        &files_before,
                        &files_after,
                    );
                }

                // Check that the new file is equivalent to the deleted files.
                if let Some(merge) = merge {
                    match merge.dst {
                        PersistDestination::OverlayFile(ref path) => {
                            verify_merge_to_overlay(path, merged_base, merged_overlays);
                        }
                        PersistDestination::BaseFile(ref path) => {
                            verify_merge_to_base(path, merged_base, merged_overlays);
                        }
                    }
                }

                check_post_merge_criteria(&files_after);

                // The directory merge should not cause any changes to the combined data.
                verify_storage(tempdir.path(), &combined_delta);
            }
        }
    }

    metrics_registry
}

/// Apply a list of `Instruction` to a new temporary directory and check correctness of the sequence
/// after every step.
fn write_overlays_and_verify(instructions: Vec<Instruction>) -> MetricsRegistry {
    let tempdir = tempdir().unwrap();
    write_overlays_and_verify_with_tempdir(instructions, &tempdir)
}

#[test]
fn corrupt_overlay_is_an_error() {
    let tempdir = tempdir().unwrap();
    write_overlays_and_verify_with_tempdir(vec![WriteOverlay(vec![9, 10])], &tempdir);
    let StorageFiles { overlays, .. } = storage_files(tempdir.path());
    assert!(overlays.len() == 1);
    let overlay_path = &overlays[0];
    let len = std::fs::metadata(overlay_path).unwrap().len();
    make_mutable(overlay_path).unwrap();
    write_all_at(overlay_path, &[0xff; 4], len - 16).unwrap();
    make_readonly(overlay_path).unwrap();

    match OverlayFile::load(overlay_path) {
        Err(PersistenceError::InvalidOverlay { path, .. }) => {
            assert_eq!(path, overlay_path.display().to_string());
        }
        _ => panic!("Overlay load must fail"),
    }
}

#[test]
fn no_back_to_back_ranges() {
    let tempdir = tempdir().unwrap();
    let path = &tempdir.path().join("000000_vmemory_0.overlay");
    {
        let mut f = File::create(path).unwrap();
        f.write_all(&[0u8; 2 * PAGE_SIZE]).unwrap();
        // 0..1
        f.write_all(&u64::to_le_bytes(0)).unwrap();
        f.write_all(&u64::to_le_bytes(0)).unwrap();
        // 1..2
        f.write_all(&u64::to_le_bytes(1)).unwrap();
        f.write_all(&u64::to_le_bytes(1)).unwrap();
        // number of pages
        f.write_all(&u64::to_le_bytes(2)).unwrap();
        // version
        f.write_all(&u32::to_le_bytes(0)).unwrap();
    }
    assert_eq!(
        std::fs::metadata(path).unwrap().len(),
        2 * PAGE_SIZE as u64 + 16 + 16 + 12
    );
    match OverlayFile::load(path) {
        Err(e) => match e {
            PersistenceError::InvalidOverlay { .. } => (),
            _ => panic!("Unexpected load error: {}", e),
        },
        _ => panic!("Overlay load must fail"),
    }
}

#[test]
fn can_write_single_page_at_zero() {
    write_overlays_and_verify(vec![WriteOverlay(vec![0])]);
}

#[test]
fn can_write_single_page_not_at_zero() {
    write_overlays_and_verify(vec![WriteOverlay(vec![10])]);
}

#[test]
fn can_write_two_separated_pages() {
    write_overlays_and_verify(vec![WriteOverlay(vec![1, 10])]);
}

#[test]
fn can_write_two_neighboring_pages() {
    write_overlays_and_verify(vec![WriteOverlay(vec![9, 10])]);
}

#[test]
fn can_write_two_seperated_pages_in_two_files() {
    write_overlays_and_verify(vec![WriteOverlay(vec![1]), WriteOverlay(vec![10])]);
}

#[test]
fn can_write_two_neighbouring_pages_in_two_files() {
    write_overlays_and_verify(vec![WriteOverlay(vec![9]), WriteOverlay(vec![10])]);
}

#[test]
fn can_overwrite_page() {
    write_overlays_and_verify(vec![WriteOverlay(vec![10]), WriteOverlay(vec![10])]);
}

#[test]
fn can_overwrite_part_of_range() {
    write_overlays_and_verify(vec![WriteOverlay(vec![9, 10]), WriteOverlay(vec![10])]);
}

#[test]
fn can_write_large_overlay_file() {
    // The index is specifically chosen to ensure the index is larger than a page, as this used to be
    // a bug. 1000 ranges of 16 bytes each is roughly 4 pages.
    let indices = (0..2000).step_by(2).collect();
    let metrics = write_overlays_and_verify(vec![WriteOverlay(indices)]);

    let metrics_index =
        maplit::btreemap!("op".into() => "flush".into(), "type".into() => "index".into());
    let index_size = fetch_int_counter_vec(&metrics, "storage_layer_write_bytes")[&metrics_index];

    assert!(index_size > PAGE_SIZE as u64);
}

#[test]
fn can_merge_large_overlay_file() {
    let mut instructions = Vec::default();
    for step in 2..10 {
        instructions.push(WriteOverlay((0..2000).step_by(step).collect()));
    }
    instructions.push(Merge {
        assert_files_merged: Some(8),
        is_downgrade: false,
    });
    write_overlays_and_verify(instructions);
}

#[test]
fn can_overwrite_and_merge_based_on_number_of_files() {
    let mut instructions = Vec::new();
    for i in 0..MAX_NUMBER_OF_FILES {
        // Create a pyramid.
        instructions.push(WriteOverlay(
            (0..2u64.pow((MAX_NUMBER_OF_FILES - i) as u32)).collect(),
        ));
    }

    instructions.push(Merge {
        assert_files_merged: None,
        is_downgrade: false,
    });

    for _ in 0..3 {
        instructions.push(WriteOverlay(vec![0]));
        // Always merge top two files to bring the number of files down to `MAX_NUMBER_OF_FILES`.
        instructions.push(Merge {
            assert_files_merged: Some(2),
            is_downgrade: false,
        });
    }

    write_overlays_and_verify(instructions);
}

#[test]
fn can_write_consecutively_and_merge_based_on_number_of_files() {
    let mut instructions = Vec::new();
    for i in 0..MAX_NUMBER_OF_FILES * 7 {
        // Write a new file.
        instructions.push(WriteOverlay(vec![20 + i as u64]));

        // Merge if needed.
        instructions.push(Merge {
            assert_files_merged: None,
            is_downgrade: false,
        });
    }

    write_overlays_and_verify(instructions);
}

#[test]
fn can_write_with_gap_and_merge_based_on_number_of_files() {
    let mut instructions = Vec::new();
    for i in 0..MAX_NUMBER_OF_FILES * 7 {
        // Write a new file.
        instructions.push(WriteOverlay(vec![20 + 2 * i as u64]));

        // Merge if needed.
        instructions.push(Merge {
            assert_files_merged: None,
            is_downgrade: false,
        });
    }

    write_overlays_and_verify(instructions);
}

#[test]
fn can_merge_all() {
    let tempdir = tempdir().unwrap();
    let mut instructions = Vec::new();
    // 5 same overlays, overhead 5x
    for _ in 0..5 {
        instructions.push(WriteOverlay((0..10).collect()));
    }

    // Merge all, reduce overhead to 1x.
    instructions.push(Merge {
        assert_files_merged: Some(5),
        is_downgrade: false,
    });

    write_overlays_and_verify_with_tempdir(instructions, &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert_eq!(storage_files.overlays.len(), 1);
    assert!(storage_files.base.is_none());
}

#[test]
fn test_num_files_to_merge() {
    assert_eq!(MergeCandidate::num_files_to_merge(&[1, 2]), Some(2));
    assert_eq!(MergeCandidate::num_files_to_merge(&[2, 1]), None);
    let make_pyramid = |levels| {
        let mut result = Vec::new();
        for i in 0..levels {
            result.push(1 << (levels - i));
        }
        result
    };
    assert_eq!(
        MergeCandidate::num_files_to_merge(&make_pyramid(MAX_NUMBER_OF_FILES)),
        None
    );
    assert_eq!(
        MergeCandidate::num_files_to_merge(&make_pyramid(MAX_NUMBER_OF_FILES + 1)),
        Some(2)
    );
    assert_eq!(
        MergeCandidate::num_files_to_merge(&make_pyramid(MAX_NUMBER_OF_FILES + 2)),
        Some(3)
    );
}

#[test]
fn test_make_merge_candidate_on_empty_dir() {
    let tempdir = tempdir().unwrap();
    let merge_candidate = MergeCandidate::new(
        &TestStorageLayout {
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_dst: tempdir.path().join("000000_vmemory_0.overlay"),
            existing_overlays: Vec::new(),
        },
        Height::from(0),
    )
    .unwrap();
    assert!(merge_candidate.is_none());
}

#[test]
fn test_make_none_merge_candidate() {
    let tempdir = tempdir().unwrap();
    // Write a single file, 10 pages.
    let instructions = vec![WriteOverlay((0..10).collect())];

    write_overlays_and_verify_with_tempdir(instructions, &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 1);

    let merge_candidate = MergeCandidate::new(
        &TestStorageLayout {
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_dst: tempdir.path().join("000000_vmemory_0.overlay"),
            existing_overlays: storage_files.overlays.clone(),
        },
        Height::from(0),
    )
    .unwrap();
    assert!(merge_candidate.is_none());
}

#[test]
fn test_make_merge_candidate_to_overlay() {
    let tempdir = tempdir().unwrap();
    // 000002 |xx|
    // 000001 |x|
    // 000000 |xxxxxxxxxx|
    // Need to merge top two to reach pyramid.
    let instructions = vec![
        WriteOverlay((0..10).collect()),
        WriteOverlay((0..1).collect()),
        WriteOverlay((0..2).collect()),
    ];

    write_overlays_and_verify_with_tempdir(instructions, &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 3);

    let merge_candidate = MergeCandidate::new(
        &TestStorageLayout {
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_dst: tempdir.path().join("000003_vmemory_0.overlay"),
            existing_overlays: storage_files.overlays.clone(),
        },
        Height::from(3),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        merge_candidate.dst,
        PersistDestination::OverlayFile(tempdir.path().join("000003_vmemory_0.overlay"))
    );
    assert!(merge_candidate.base.is_none());
    assert_eq!(merge_candidate.overlays, storage_files.overlays[1..3]);
}

#[test]
fn test_make_merge_candidate_to_base() {
    let tempdir = tempdir().unwrap();
    // 000001 |xx|
    // 000000 |x|
    // Need to merge all two to reach pyramid.
    let instructions = vec![
        WriteOverlay((0..1).collect()),
        WriteOverlay((0..2).collect()),
    ];

    write_overlays_and_verify_with_tempdir(instructions, &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 2);

    let merge_candidate = MergeCandidate::merge_to_base(&TestStorageLayout {
        base: tempdir.path().join("vmemory_0.bin"),
        overlay_dst: tempdir.path().join("000003_vmemory_0.overlay"),
        existing_overlays: storage_files.overlays.clone(),
    })
    .unwrap()
    .unwrap();
    assert_eq!(
        merge_candidate.dst,
        PersistDestination::BaseFile(tempdir.path().join("vmemory_0.bin"))
    );
    assert!(merge_candidate.base.is_none());
    assert_eq!(merge_candidate.overlays, storage_files.overlays);
}

#[test]
fn test_two_same_length_files_are_a_pyramid() {
    let tempdir = tempdir().unwrap();
    // 000001 |xx|
    // 000000 |xx|
    // No need to merge.
    let instructions = vec![
        WriteOverlay((0..2).collect()),
        WriteOverlay((0..2).collect()),
    ];

    write_overlays_and_verify_with_tempdir(instructions, &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 2);

    let merge_candidate = MergeCandidate::new(
        &TestStorageLayout {
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_dst: tempdir.path().join("000003_vmemory_0.overlay"),
            existing_overlays: storage_files.overlays.clone(),
        },
        Height::from(0),
    )
    .unwrap();
    assert!(merge_candidate.is_none());
}

#[test]
fn can_get_small_memory_regions_from_file() {
    let indices = vec![9, 10, 11, 19, 20, 21, 22, 23];

    let tempdir = tempdir().unwrap();
    let path = &tempdir.path().join("0_vmemory_0.overlay");

    let allocator = PageAllocator::new_for_testing();
    let metrics = StorageMetrics::new(&MetricsRegistry::new());

    let data = &[42_u8; PAGE_SIZE];
    let overlay_pages: Vec<_> = indices.iter().map(|i| (PageIndex::new(*i), data)).collect();

    let delta = PageDelta::from(allocator.allocate(&overlay_pages));

    OverlayFile::write(&delta, path, &metrics).unwrap();
    let overlay = OverlayFile::load(path).unwrap();
    let range = PageIndex::new(0)..PageIndex::new(30);

    // Call `get_memory_instructions` with an empty filter.
    let mut empty_filter = BitVec::from_elem((range.end.get() - range.start.get()) as usize, false);
    let actual_instructions =
        overlay.get_memory_instructions(PageIndex::new(0)..PageIndex::new(30), &mut empty_filter);

    assert_eq!(actual_instructions.len(), indices.len());
    for (_range, instruction) in actual_instructions {
        assert_matches!(instruction, MemoryMapOrData::Data { .. });
    }

    // Check that filter was updated correctly.
    let mut expected_filter =
        BitVec::from_elem((range.end.get() - range.start.get()) as usize, false);
    for index in &indices {
        expected_filter.set(*index as usize, true);
    }
    assert_eq!(empty_filter, expected_filter);

    // Call `get_memory_instructions` with a nonempty filter.
    let mut nonempty_filter =
        BitVec::from_elem((range.end.get() - range.start.get()) as usize, false);
    nonempty_filter.set(9, true); // Present in `indices`.
    nonempty_filter.set(11, true); // Present in `indices`.
    nonempty_filter.set(12, true); // Not present in `indices`.
    let actual_instructions = overlay
        .get_memory_instructions(PageIndex::new(0)..PageIndex::new(30), &mut nonempty_filter);

    assert_eq!(actual_instructions.len(), indices.len() - 2); // 2 results are filtered out.
    for (_range, instruction) in actual_instructions {
        assert_matches!(instruction, MemoryMapOrData::Data { .. });
    }

    // This covers more generic checks with this input.
    write_overlays_and_verify(vec![WriteOverlay(indices)]);
}

#[test]
fn can_get_large_memory_regions_from_file() {
    let indices = vec![9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

    let tempdir = tempdir().unwrap();
    let path = &tempdir.path().join("0_vmemory_0.overlay");

    let allocator = PageAllocator::new_for_testing();
    let metrics = StorageMetrics::new(&MetricsRegistry::new());

    let data = &[42_u8; PAGE_SIZE];
    let overlay_pages: Vec<_> = indices.iter().map(|i| (PageIndex::new(*i), data)).collect();

    let delta = PageDelta::from(allocator.allocate(&overlay_pages));

    OverlayFile::write(&delta, path, &metrics).unwrap();
    let overlay = OverlayFile::load(path).unwrap();
    let range = PageIndex::new(0)..PageIndex::new(30);

    // Call `get_memory_instructions` with an empty filter.
    let mut empty_filter = BitVec::from_elem((range.end.get() - range.start.get()) as usize, false);
    let actual_instructions =
        overlay.get_memory_instructions(PageIndex::new(0)..PageIndex::new(30), &mut empty_filter);

    assert_eq!(actual_instructions.len(), 1);
    let (mmap_range, instruction) = &actual_instructions[0];
    assert_eq!(*mmap_range, PageIndex::new(9)..PageIndex::new(21));
    assert_matches!(instruction, MemoryMapOrData::MemoryMap { .. });

    // Check that filter was updated correctly.
    let mut expected_filter =
        BitVec::from_elem((range.end.get() - range.start.get()) as usize, false);
    for index in &indices {
        expected_filter.set(*index as usize, true);
    }
    assert_eq!(empty_filter, expected_filter);

    // Call `get_memory_instructions` with a nonempty filter that still results in a memory map.
    let mut nonempty_filter =
        BitVec::from_elem((range.end.get() - range.start.get()) as usize, false);
    nonempty_filter.set(9, true); // Present in `indices`.
    nonempty_filter.set(25, true); // Not present in `indices`.
    let actual_instructions = overlay
        .get_memory_instructions(PageIndex::new(0)..PageIndex::new(30), &mut nonempty_filter);

    assert_eq!(actual_instructions.len(), 1);
    let (mmap_range, instruction) = &actual_instructions[0];
    assert_eq!(*mmap_range, PageIndex::new(9)..PageIndex::new(21));
    assert_matches!(instruction, MemoryMapOrData::MemoryMap { .. });

    // Call `get_memory_instructions` with a nonempty filter that so that we copy instead.
    let mut nonempty_filter =
        BitVec::from_elem((range.end.get() - range.start.get()) as usize, false);
    nonempty_filter.set(9, true); // Present in `indices`.
    nonempty_filter.set(11, true); // Present in `indices`.
    nonempty_filter.set(25, true); // Not present in `indices`.
    let actual_instructions = overlay
        .get_memory_instructions(PageIndex::new(0)..PageIndex::new(30), &mut nonempty_filter);

    assert_eq!(actual_instructions.len(), indices.len() - 2); // 9, 11 should be missing
    for (_range, instruction) in actual_instructions {
        assert_matches!(instruction, MemoryMapOrData::Data { .. });
    }

    // This covers more generic checks with this input.
    write_overlays_and_verify(vec![WriteOverlay(indices)]);
}

#[test]
fn overlay_version_is_current() {
    let indices = [9, 10, 11, 19, 20, 21, 22, 23];

    let tempdir = tempdir().unwrap();
    let path = &tempdir.path().join("0_vmemory_0.overlay");

    let allocator = PageAllocator::new_for_testing();
    let metrics = StorageMetrics::new(&MetricsRegistry::new());

    let data = &[42_u8; PAGE_SIZE];
    let overlay_pages: Vec<_> = indices.iter().map(|i| (PageIndex::new(*i), data)).collect();

    let delta = PageDelta::from(allocator.allocate(&overlay_pages));

    OverlayFile::write(&delta, path, &metrics).unwrap();
    let overlay = OverlayFile::load(path).unwrap();
    let version = overlay.version();
    assert_eq!(version, CURRENT_OVERLAY_VERSION);
}

mod proptest_tests {
    use super::*;
    use proptest::collection::vec as prop_vec;
    use proptest::prelude::*;

    /// A random individual instruction.
    fn instruction_strategy() -> impl Strategy<Value = Instruction> {
        prop_oneof![
            prop_vec(0..100_u64, 1..50).prop_map(|mut vec| {
                vec.sort();
                vec.dedup();
                WriteOverlay(vec)
            }),
            Just(Merge {
                assert_files_merged: None,
                is_downgrade: false,
            }),
            Just(Merge {
                assert_files_merged: None,
                is_downgrade: true,
            }),
        ]
    }

    /// A random vector of instructions.
    fn instructions_strategy() -> impl Strategy<Value = Vec<Instruction>> {
        prop_vec(instruction_strategy(), 1..20)
    }

    proptest! {
        #[test]
        fn random_instructions(instructions in instructions_strategy()) {
            write_overlays_and_verify(instructions);
        }
    }
}
