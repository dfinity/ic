#![cfg_attr(feature = "fuzzing_code", allow(dead_code, unused_imports))]
use std::{
    collections::BTreeMap,
    fs::File,
    io::Write,
    os::{fd::FromRawFd, unix::prelude::FileExt},
    path::{Path, PathBuf},
};

use crate::page_map::{
    storage::{
        Checkpoint, FileIndex, MergeCandidate, MergeDestination, OverlayFile, PageIndexRange,
        Shard, Storage, StorageLayout, CURRENT_OVERLAY_VERSION, PAGE_INDEX_RANGE_NUM_BYTES,
        SIZE_NUM_BYTES, VERSION_NUM_BYTES,
    },
    test_utils::{ShardedTestStorageLayout, TestStorageLayout},
    FileDescriptor, MemoryInstructions, MemoryMapOrData, PageAllocator, PageDelta, PageMap,
    PersistenceError, StorageMetrics, MAX_NUMBER_OF_FILES,
};
use assert_matches::assert_matches;
use bit_vec::BitVec;
use ic_config::flag_status::FlagStatus;
use ic_config::state_manager::LsmtConfig;
use ic_metrics::MetricsRegistry;
use ic_sys::{PageIndex, PAGE_SIZE};
use ic_test_utilities_io::{make_mutable, make_readonly, write_all_at};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::Height;
use tempfile::{tempdir, Builder, TempDir};

#[cfg(feature = "fuzzing_code")]
use arbitrary::Arbitrary;

/// The expected size of an overlay file.
///
/// The expectation is based on how many pages the overlay contains and how many distinct
/// ranges of indices there are.
fn expected_overlay_file_size(num_pages: u64, num_ranges: u64) -> u64 {
    // We should not create overlays for zero pages.
    assert!(num_pages != 0);
    let data = num_pages * PAGE_SIZE as u64;
    let index = num_ranges * PAGE_INDEX_RANGE_NUM_BYTES as u64;

    data + index + SIZE_NUM_BYTES as u64 + VERSION_NUM_BYTES as u64
}

/// Division with rounding up, e.g. 2 / 2 -> 1, 1 / 2 -> 1
fn divide_rounding_up(a: u64, b: u64) -> u64 {
    a / b + if a % b != 0 { 1 } else { 0 }
}

/// Expected sizes of the shards; 0 if the shards has no data and should not exist.
fn expected_shard_sizes(delta: &PageDelta, shard_num_pages: u64) -> Vec<u64> {
    let num_shards = divide_rounding_up(delta.max_page_index().unwrap().get() + 1, shard_num_pages);
    let mut num_separate_ranges_by_shard = vec![0; num_shards as usize];
    let mut num_pages_by_shard = vec![0; num_shards as usize];
    let mut last_index = None;
    for (key, _) in delta.iter() {
        let key = key.get();
        let shard = (key / shard_num_pages) as usize;
        if last_index.is_none() || last_index.unwrap() != key - 1 || key % shard_num_pages == 0 {
            num_separate_ranges_by_shard[shard] += 1;
        }
        num_pages_by_shard[shard] += 1;
        last_index = Some(key);
    }
    (0..num_shards)
        .map(|shard| {
            if num_pages_by_shard[shard as usize] == 0 {
                0
            } else {
                expected_overlay_file_size(
                    num_pages_by_shard[shard as usize],
                    num_separate_ranges_by_shard[shard as usize],
                )
            }
        })
        .collect()
}

/// Verify that the (potentially sharded) overlay at height `height` is identical to the
/// data in `expected` page delta.
fn verify_overlays(
    layout: &dyn StorageLayout,
    height: Height,
    lsmt_config: &LsmtConfig,
    expected: &PageDelta,
) {
    let existing_shards: BTreeMap<Shard, OverlayFile> = layout
        .existing_overlays()
        .unwrap()
        .into_iter()
        .filter(|p| layout.overlay_height(p).unwrap() == height)
        .map(|p| {
            (
                layout.overlay_shard(&p).unwrap(),
                OverlayFile::load(&p).unwrap(),
            )
        })
        .collect();
    let expected_shard_sizes = expected_shard_sizes(expected, lsmt_config.shard_num_pages);
    // Check number of shards.
    assert_eq!(
        existing_shards.last_key_value().unwrap().0.get() as usize + 1,
        expected_shard_sizes.len(),
    );
    // Check the sizes of individual shards.
    for (shard, size) in expected_shard_sizes.into_iter().enumerate() {
        assert_eq!(
            layout
                .overlay(height, Shard::new(shard as u64))
                .metadata()
                .map_or(0, |m| m.len()),
            size,
            "Shard: {}",
            shard
        );
    }
    // Check that the content of expected page delta matches the overlays.
    let zeroes = [0; PAGE_SIZE];
    for page in 0..expected.0.len() as u64 {
        let shard = page / lsmt_config.shard_num_pages;
        match (
            existing_shards
                .get(&Shard::new(shard))
                .and_then(|overlay| overlay.get_page(PageIndex::new(page))),
            expected.get_page(PageIndex::new(page)),
        ) {
            (Some(overlay), Some(delta)) => assert_eq!(overlay, delta),
            (None, Some(delta)) => assert_eq!(delta, &zeroes),
            (Some(overlay), None) => panic!("Overlay: {:#?}", overlay),
            (None, None) => (),
        }
    }
    // Check the overlay is sharded properly.
    for (shard, overlay_file) in existing_shards {
        for (page_index, _) in overlay_file.iter() {
            assert!(page_index.get() >= shard.get() * lsmt_config.shard_num_pages);
            assert!(page_index.get() < (shard.get() + 1) * lsmt_config.shard_num_pages);
            assert!(page_index.get() <= expected.max_page_index().unwrap().get());
        }
    }
}

/// Read all data in input files as PageDelta.
fn files_as_delta(base: &Option<Checkpoint>, overlays: &[OverlayFile]) -> PageDelta {
    let allocator = PageAllocator::new_for_testing();
    let mut pages = Vec::default();
    let num_logical_pages = overlays
        .iter()
        .map(|f| f.end_logical_pages())
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
fn check_post_merge_criteria(storage_files: &StorageFiles, layout: &ShardedTestStorageLayout) {
    let base_length: Vec<u64> = storage_files
        .base
        .iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .collect();
    let mut file_lengths_by_shard: BTreeMap<Shard, Vec<u64>> = BTreeMap::new();
    for p in storage_files.overlays.iter() {
        file_lengths_by_shard
            .entry(layout.overlay_shard(p).unwrap())
            .or_insert(base_length.clone())
            .push(std::fs::metadata(p).unwrap().len());
    }
    for file_lengths in file_lengths_by_shard.values() {
        assert!(file_lengths.len() <= MAX_NUMBER_OF_FILES);
        file_lengths
            .iter()
            .rev()
            .fold(0, |size_on_top, current_size| {
                assert!(size_on_top <= *current_size);
                size_on_top + current_size
            });
    }
}

/// Verify that the data in `new_base` is the same as in `old_base` + `old_files`.
fn verify_merge_to_base(
    new_base: &Path,
    old_base: &Option<Checkpoint>,
    old_overlays: &[OverlayFile],
) {
    let delta = files_as_delta(old_base, old_overlays);
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

/// Verify that the data in `new_overlay` is the same as in `old_base` + `old_files`.
fn verify_merge_to_overlay(
    new_overlay: &[PathBuf],
    old_base: &Option<Checkpoint>,
    old_overlays: &[OverlayFile],
    layout: &dyn StorageLayout,
    lsmt_config: &LsmtConfig,
) {
    let delta = files_as_delta(old_base, old_overlays);
    let dst: BTreeMap<Shard, OverlayFile> = new_overlay
        .iter()
        .filter(|p| p.exists())
        .map(|p| {
            (
                layout.overlay_shard(p).unwrap(),
                OverlayFile::load(p).unwrap(),
            )
        })
        .collect();
    let num_logical_pages = dst
        .values()
        .map(|o| o.end_logical_pages() as u64)
        .max()
        .unwrap();
    assert_eq!(delta.iter().last().unwrap().0.get() + 1, num_logical_pages);
    let zeroes = [0; PAGE_SIZE];
    for i in 0..num_logical_pages {
        let page_index = PageIndex::new(i);
        let shard = Shard::new(page_index.get() / lsmt_config.shard_num_pages);
        match (
            delta.get_page(page_index),
            dst.get(&shard).and_then(|o| o.get_page(page_index)),
        ) {
            (Some(data_delta), Some(data_dst)) => assert_eq!(data_delta, data_dst),
            (None, Some(data_dst)) => assert_eq!(&zeroes, data_dst),
            (Some(data_delta), None) => assert_eq!(&zeroes, data_delta),
            (None, None) => (),
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

#[derive(Clone, Eq, PartialEq, Debug)]
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
    let storage_layout = ShardedTestStorageLayout {
        dir_path: dir.to_path_buf(),
        base: dir.join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".to_owned(),
    };
    let storage = Storage::load(&storage_layout).unwrap();

    let expected_num_pages = if let Some(max) = expected.max_page_index() {
        max.get() + 1
    } else {
        // `delta` is empty in this case.
        0
    };

    // Verify `num_logical_pages`.
    assert_eq!(expected_num_pages, storage.num_logical_pages() as u64);
    assert_eq!(
        expected_num_pages as usize,
        (&storage_layout as &dyn StorageLayout)
            .memory_size_pages()
            .unwrap()
    );

    // Verify every single page in the range.
    for index in 0..storage.num_logical_pages() as u64 {
        let index = PageIndex::new(index);
        assert_eq!(
            storage.get_page(index),
            expected.get_page(index).unwrap_or(&[0; PAGE_SIZE]),
            "Index: {}",
            index.get()
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
    merge_files: &[usize],
    before: &StorageFiles,
    after: &StorageFiles,
    layout: &ShardedTestStorageLayout,
) {
    let num_shards_after = after
        .overlays
        .iter()
        .map(|o| layout.overlay_shard(o).unwrap().get() + 1)
        .max()
        .unwrap_or(after.base.iter().len() as u64);
    assert_eq!(merge_files.len() as u64, num_shards_after);
    for i in 0..num_shards_after {
        let before_len = before.base.iter().len()
            + before
                .overlays
                .iter()
                .filter(|o| layout.overlay_shard(o).unwrap().get() == i)
                .count();
        let after_len = after.base.iter().len()
            + after
                .overlays
                .iter()
                .filter(|o| layout.overlay_shard(o).unwrap().get() == i)
                .count();
        let merge_files = merge_files[i as usize];
        if merge_files == 0 {
            assert_eq!(before_len, after_len);
        } else {
            assert_eq!(before_len - after_len + 1, merge_files);
        }
    }
}

/// An instruction to modify a storage.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzzing_code", derive(Arbitrary))]
pub enum Instruction {
    /// Create an overlay file with provided list of `PageIndex` to write.
    WriteOverlay(Vec<u64>),
    /// Create & apply `MergeCandidate`; check for amount of files merged.
    Merge {
        is_downgrade: bool,
        assert_files_merged: Option<Vec<usize>>,
    },
}
use Instruction::*;

/// Write the `delta` as overlay file.
fn write_overlay(
    delta: &PageDelta,
    path: &Path,
    height: Height,
    metrics: &StorageMetrics,
) -> Result<(), PersistenceError> {
    let storage_layout = TestStorageLayout {
        base: "".into(),
        overlay_dst: path.to_path_buf(),
        existing_overlays: Vec::new(),
    };
    OverlayFile::write(
        delta,
        &storage_layout,
        height,
        &LsmtConfig {
            lsmt_status: FlagStatus::Enabled,
            shard_num_pages: u64::MAX,
        },
        metrics,
    )
}

fn lsmt_config_unsharded() -> LsmtConfig {
    LsmtConfig {
        lsmt_status: FlagStatus::Enabled,
        shard_num_pages: u64::MAX,
    }
}

fn lsmt_config_sharded() -> LsmtConfig {
    LsmtConfig {
        lsmt_status: FlagStatus::Enabled,
        shard_num_pages: 3,
    }
}

/// This function applies `instructions` to a new `Storage` in a temporary directory.
/// At the same time, we apply the same instructions to a `PageDelta`, which acts as the reference
/// implementation. After each operation, we check that all overlay files are as expected and
/// correspond to the reference.
fn write_overlays_and_verify_with_tempdir(
    instructions: Vec<Instruction>,
    lsmt_config: &LsmtConfig,
    tempdir: &TempDir,
) -> MetricsRegistry {
    let allocator = PageAllocator::new_for_testing();
    let metrics_registry = MetricsRegistry::new();
    let metrics = StorageMetrics::new(&metrics_registry);

    let mut combined_delta = PageDelta::default();

    let storage_layout = ShardedTestStorageLayout {
        dir_path: tempdir.path().to_path_buf(),
        base: tempdir.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".to_owned(),
    };

    for (round, instruction) in instructions.iter().enumerate() {
        match instruction {
            WriteOverlay(round_indices) => {
                let data = &[round as u8; PAGE_SIZE];
                let overlay_pages: Vec<_> = round_indices
                    .iter()
                    .map(|i| (PageIndex::new(*i), data))
                    .collect();

                let delta = PageDelta::from(allocator.allocate(&overlay_pages));

                OverlayFile::write(
                    &delta,
                    &storage_layout,
                    Height::new(round as u64),
                    lsmt_config,
                    &metrics,
                )
                .unwrap();
                // Check both the sharded overlay we just wrote and the resulting directory for correctness.
                verify_overlays(
                    &storage_layout,
                    Height::new(round as u64),
                    lsmt_config,
                    &delta,
                );

                combined_delta.update(delta);

                verify_storage(tempdir.path(), &combined_delta);
            }

            Merge {
                is_downgrade,
                assert_files_merged,
            } => {
                let files_before = storage_files(tempdir.path());
                let mut page_map = PageMap::new_for_testing();
                let num_pages = combined_delta
                    .max_page_index()
                    .map_or(0, |index| index.get() + 1);
                page_map.update(
                    combined_delta
                        .iter()
                        .map(|(i, p)| (i, p.contents()))
                        .collect::<Vec<_>>()
                        .as_slice(),
                );

                let merges = if *is_downgrade {
                    MergeCandidate::merge_to_base(&storage_layout, num_pages)
                        .unwrap()
                        .into_iter()
                        .collect::<Vec<_>>()
                } else {
                    MergeCandidate::new(
                        &storage_layout,
                        Height::from(round as u64),
                        num_pages,
                        lsmt_config,
                        &metrics,
                    )
                    .unwrap()
                };
                // Open the files before they might get deleted.
                let merged_overlays: Vec<(Shard, OverlayFile)> = merges
                    .iter()
                    .flat_map(|m| {
                        m.overlays.iter().map(|path| {
                            (
                                storage_layout.overlay_shard(path).unwrap(),
                                OverlayFile::load(path).unwrap(),
                            )
                        })
                    })
                    .collect();
                let merged_base = if merges.len() == 1 {
                    merges[0]
                        .base
                        .as_ref()
                        .map(|path| Checkpoint::open(path).unwrap())
                } else {
                    None
                };

                for merge in &merges {
                    merge.apply(&metrics).unwrap();
                }

                let files_after = storage_files(tempdir.path());

                if let Some(assert_files_merged) = assert_files_merged {
                    merge_assert_num_files(
                        assert_files_merged,
                        &files_before,
                        &files_after,
                        &storage_layout,
                    );
                }

                // Check that the new file is equivalent to the deleted files.
                for merge in merges.iter() {
                    match &merge.dst {
                        MergeDestination::MultiShardOverlay { shard_paths, .. } => {
                            verify_merge_to_overlay(
                                shard_paths,
                                &merged_base,
                                &merged_overlays
                                    .iter()
                                    .map(|(_, o)| o.clone())
                                    .collect::<Vec<_>>(),
                                &storage_layout,
                                lsmt_config,
                            );
                        }
                        MergeDestination::BaseFile(ref path) => {
                            verify_merge_to_base(
                                path,
                                &merged_base,
                                &merged_overlays
                                    .iter()
                                    .map(|(_, o)| o.clone())
                                    .collect::<Vec<_>>(),
                            );
                        }
                        MergeDestination::SingleShardOverlay(path) => {
                            verify_merge_to_overlay(
                                &[path.clone()],
                                &merged_base,
                                &merged_overlays
                                    .iter()
                                    .filter(|(s, _)| {
                                        *s == storage_layout.overlay_shard(path).unwrap()
                                    })
                                    .map(|(_, o)| o.clone())
                                    .collect::<Vec<_>>(),
                                &storage_layout,
                                lsmt_config,
                            );
                        }
                    }
                }

                check_post_merge_criteria(&files_after, &storage_layout);

                // The directory merge should not cause any changes to the combined data.
                verify_storage(tempdir.path(), &combined_delta);
            }
        }
    }

    metrics_registry
}

/// Apply a list of `Instruction` to a new temporary directory and check correctness of the sequence
/// after every step.
/// Use unsharded LSMT config.
fn write_overlays_and_verify_unsharded(instructions: Vec<Instruction>) -> MetricsRegistry {
    let tempdir = Builder::new()
        .prefix("write_overlays_and_verify_unsharded")
        .tempdir()
        .unwrap();
    let metrics =
        write_overlays_and_verify_with_tempdir(instructions, &lsmt_config_unsharded(), &tempdir);
    tempdir
        .close()
        .expect("Unable to delete temporary directory");
    metrics
}

/// Apply a list of `Instruction` to a new temporary directory and check correctness of the sequence
/// after every step.
/// Use sharded LSMT config
fn write_overlays_and_verify_sharded(instructions: Vec<Instruction>) -> MetricsRegistry {
    let tempdir = Builder::new()
        .prefix("write_overlays_and_verify_sharded")
        .tempdir()
        .unwrap();
    let metrics =
        write_overlays_and_verify_with_tempdir(instructions, &lsmt_config_sharded(), &tempdir);
    tempdir
        .close()
        .expect("Unable to delete temporary directory");
    metrics
}

/// Apply a list of `Instruction` to a new temporary directory and check correctness of the sequence
/// after every step for both sharded and unsharded config
pub fn write_overlays_and_verify(instructions: Vec<Instruction>) {
    write_overlays_and_verify_sharded(instructions.clone());
    write_overlays_and_verify_unsharded(instructions);
}

#[test]
fn corrupt_overlay_is_an_error() {
    let tempdir = tempdir().unwrap();
    write_overlays_and_verify_with_tempdir(
        vec![WriteOverlay(vec![9, 10])],
        &lsmt_config_unsharded(),
        &tempdir,
    );
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
    let metrics = write_overlays_and_verify_unsharded(vec![WriteOverlay(indices)]);

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
        assert_files_merged: Some(vec![8]),
        is_downgrade: false,
    });
    write_overlays_and_verify_unsharded(instructions);
}

#[test]
fn can_overwrite_and_merge_based_on_number_of_files() {
    let mut instructions: Vec<_> = make_pyramid(MAX_NUMBER_OF_FILES)
        .into_iter()
        .map(|size| WriteOverlay((0..size).collect::<Vec<_>>()))
        .collect();

    instructions.push(Merge {
        assert_files_merged: Some(vec![0]),
        is_downgrade: false,
    });

    for _ in 0..3 {
        instructions.push(WriteOverlay(vec![0]));
        // Always merge top two files to bring the number of files down to `MAX_NUMBER_OF_FILES`.
        instructions.push(Merge {
            assert_files_merged: Some(vec![2]),
            is_downgrade: false,
        });
    }

    write_overlays_and_verify_unsharded(instructions);
}

#[test]
fn can_merge_single_shard_out_of_few() {
    write_overlays_and_verify_sharded(vec![
        WriteOverlay((0..9).collect::<Vec<_>>()),
        WriteOverlay((3..6).collect::<Vec<_>>()),
        WriteOverlay((3..6).collect::<Vec<_>>()),
        WriteOverlay((3..6).collect::<Vec<_>>()),
        Merge {
            assert_files_merged: Some(vec![0, 4, 0]),
            is_downgrade: false,
        },
    ]);
}

#[test]
fn can_downgrade_and_reshard() {
    write_overlays_and_verify_sharded(vec![
        WriteOverlay((0..9).collect::<Vec<_>>()),
        Merge {
            assert_files_merged: None,
            is_downgrade: true,
        },
        WriteOverlay((0..1).collect::<Vec<_>>()),
        Merge {
            assert_files_merged: Some(vec![2, 1, 1]),
            is_downgrade: false,
        },
    ]);
}

#[test]
fn wrong_shard_pages_is_an_error() {
    let tempdir = tempdir().unwrap();
    write_overlays_and_verify_with_tempdir(
        vec![
            WriteOverlay((0..9).collect::<Vec<_>>()),
            WriteOverlay((0..9).collect::<Vec<_>>()),
            WriteOverlay((0..9).collect::<Vec<_>>()),
        ],
        &LsmtConfig {
            lsmt_status: FlagStatus::Enabled,
            shard_num_pages: 4,
        },
        &tempdir,
    );
    let merge_candidates = MergeCandidate::new(
        &ShardedTestStorageLayout {
            dir_path: tempdir.path().to_path_buf(),
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_suffix: "vmemory_0.overlay".to_owned(),
        },
        Height::from(0),
        9, /* num_pages */
        &LsmtConfig {
            lsmt_status: FlagStatus::Enabled,
            shard_num_pages: 3,
        },
        &StorageMetrics::new(&MetricsRegistry::new()),
    )
    .unwrap();
    assert!(!merge_candidates.is_empty());
    assert!(std::panic::catch_unwind(|| merge_candidates[0]
        .apply(&StorageMetrics::new(&MetricsRegistry::new()))
        .unwrap())
    .is_err());
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
        assert_files_merged: Some(vec![5]),
        is_downgrade: false,
    });

    write_overlays_and_verify_with_tempdir(instructions, &lsmt_config_unsharded(), &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert_eq!(storage_files.overlays.len(), 1);
    assert!(storage_files.base.is_none());
}

fn make_pyramid(levels: usize) -> Vec<u64> {
    let mut result = Vec::new();
    if levels > 0 {
        result.push(1_u64 << (levels + 2));
    }
    for i in 1..levels {
        result.push(1 << (levels - i));
    }
    result
}

#[test]
fn test_num_files_to_merge() {
    assert_eq!(MergeCandidate::num_files_to_merge(&[1, 2]), Some(2));
    assert_eq!(MergeCandidate::num_files_to_merge(&[2, 1]), Some(2));
    assert_eq!(MergeCandidate::num_files_to_merge(&[5, 1]), None);

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
fn test_make_merge_candidates_on_empty_dir() {
    let tempdir = tempdir().unwrap();
    let merge_candidates = MergeCandidate::new(
        &ShardedTestStorageLayout {
            dir_path: tempdir.path().to_path_buf(),
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_suffix: "vmemory_0.overlay".to_owned(),
        },
        Height::from(0),
        0, /* num_pages */
        &lsmt_config_unsharded(),
        &StorageMetrics::new(&MetricsRegistry::new()),
    )
    .unwrap();
    assert!(merge_candidates.is_empty());
}

#[test]
fn test_make_none_merge_candidate() {
    let tempdir = tempdir().unwrap();
    // Write a single file, 10 pages.
    let instructions = vec![WriteOverlay((0..10).collect())];

    write_overlays_and_verify_with_tempdir(instructions, &lsmt_config_unsharded(), &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 1);

    let merge_candidates = MergeCandidate::new(
        &ShardedTestStorageLayout {
            dir_path: tempdir.path().to_path_buf(),
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_suffix: "vmemory_0.overlay".to_owned(),
        },
        Height::from(0),
        10, /* num_pages */
        &lsmt_config_unsharded(),
        &StorageMetrics::new(&MetricsRegistry::new()),
    )
    .unwrap();
    assert!(merge_candidates.is_empty());
}

#[test]
fn test_make_merge_candidates_to_overlay() {
    let tempdir = tempdir().unwrap();
    let lsmt_config = LsmtConfig {
        lsmt_status: FlagStatus::Enabled,
        shard_num_pages: 15,
    };

    // 000002 |xx|
    // 000001 |x|
    // 000000 |xx...x| |xx...x| |xx...x|
    // Need to merge top two to reach pyramid.
    let instructions = vec![
        WriteOverlay((0..40).collect()), // 3 files created
        WriteOverlay((0..1).collect()),  // 1 file created
        WriteOverlay((0..2).collect()),  // 1 file created
    ];

    write_overlays_and_verify_with_tempdir(instructions, &lsmt_config, &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 5);

    let merge_candidates = MergeCandidate::new(
        &ShardedTestStorageLayout {
            dir_path: tempdir.path().to_path_buf(),
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_suffix: "vmemory_0.overlay".to_owned(),
        },
        Height::from(3),
        40, /* num_pages */
        &lsmt_config,
        &StorageMetrics::new(&MetricsRegistry::new()),
    )
    .unwrap();
    assert_eq!(merge_candidates.len(), 1);
    assert_eq!(
        merge_candidates[0].dst,
        MergeDestination::SingleShardOverlay(tempdir.path().join("000003_000_vmemory_0.overlay"))
    );
    assert!(merge_candidates[0].base.is_none());
    assert_eq!(merge_candidates[0].overlays, storage_files.overlays[3..5]);
    assert_eq!(merge_candidates[0].num_files_before, 3); // only shard 0 to be merged, containing 3 overlays
    assert_eq!(
        merge_candidates[0].storage_size_bytes_before,
        [
            &storage_files.overlays[0],
            &storage_files.overlays[3],
            &storage_files.overlays[4]
        ]
        .iter()
        .map(|p| p.metadata().unwrap().len())
        .sum::<u64>()
    );
    assert_eq!(
        merge_candidates[0].input_size_bytes,
        storage_files.overlays[3..5]
            .iter()
            .map(|p| p.metadata().unwrap().len())
            .sum::<u64>()
    );
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

    write_overlays_and_verify_with_tempdir(instructions, &lsmt_config_unsharded(), &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 2);

    let merge_candidate = MergeCandidate::merge_to_base(
        &ShardedTestStorageLayout {
            dir_path: tempdir.path().to_path_buf(),
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_suffix: "vmemory_0.overlay".to_owned(),
        },
        3,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        merge_candidate.dst,
        MergeDestination::BaseFile(tempdir.path().join("vmemory_0.bin"))
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
        WriteOverlay((0..9).collect()),
        WriteOverlay((0..2).collect()),
    ];

    write_overlays_and_verify_with_tempdir(instructions, &lsmt_config_unsharded(), &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 2);

    let merge_candidates = MergeCandidate::new(
        &ShardedTestStorageLayout {
            dir_path: tempdir.path().to_path_buf(),
            base: tempdir.path().join("vmemory_0.bin"),
            overlay_suffix: "vmemory_0.overlay".to_owned(),
        },
        Height::from(0),
        2, /* num_pages */
        &lsmt_config_unsharded(),
        &StorageMetrics::new(&MetricsRegistry::new()),
    )
    .unwrap();
    assert!(merge_candidates.is_empty());
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

    write_overlay(&delta, path, Height::new(0), &metrics).unwrap();
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
    write_overlay(&delta, path, Height::new(0), &metrics).unwrap();
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

    write_overlay(&delta, path, Height::new(0), &metrics).unwrap();
    let overlay = OverlayFile::load(path).unwrap();
    let version = overlay.version();
    assert_eq!(version, CURRENT_OVERLAY_VERSION);
}

#[test]
fn can_write_shards() {
    let tempdir = tempdir().unwrap();

    let instructions = vec![WriteOverlay(vec![9, 10])];

    write_overlays_and_verify_with_tempdir(
        instructions,
        &LsmtConfig {
            lsmt_status: FlagStatus::Enabled,
            shard_num_pages: 1,
        },
        &tempdir,
    );
    let files = storage_files(tempdir.path());
    assert!(files.base.is_none());
    assert_eq!(
        files.overlays,
        vec![
            tempdir.path().join("000000_009_vmemory_0.overlay"),
            tempdir.path().join("000000_010_vmemory_0.overlay"),
        ]
    );
}

#[test]
fn overlapping_shards_is_an_error() {
    let tempdir = tempdir().unwrap();

    let instructions = vec![WriteOverlay(vec![9, 10])];

    write_overlays_and_verify_with_tempdir(
        instructions,
        &LsmtConfig {
            lsmt_status: FlagStatus::Enabled,
            shard_num_pages: 1,
        },
        &tempdir,
    );
    let files = storage_files(tempdir.path());
    assert_eq!(
        files.overlays,
        vec![
            tempdir.path().join("000000_009_vmemory_0.overlay"),
            tempdir.path().join("000000_010_vmemory_0.overlay"),
        ]
    );
    assert!(Storage::load(&ShardedTestStorageLayout {
        dir_path: tempdir.path().to_path_buf(),
        base: tempdir.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".to_owned(),
    })
    .is_ok());
    std::fs::copy(
        tempdir.path().join("000000_010_vmemory_0.overlay"),
        tempdir.path().join("000000_011_vmemory_0.overlay"),
    )
    .unwrap();
    assert!(Storage::load(&ShardedTestStorageLayout {
        dir_path: tempdir.path().to_path_buf(),
        base: tempdir.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".to_owned(),
    })
    .is_err());
}
#[test]
fn sharded_base_file() {
    // Base only files; expect get_base_memory_instructions to be exhaustive
    let dir = tempdir().unwrap();
    write_overlays_and_verify_with_tempdir(
        vec![WriteOverlay(vec![1, 10]), WriteOverlay(vec![5])],
        &lsmt_config_sharded(),
        &dir,
    );
    let storage = Storage::load(&ShardedTestStorageLayout {
        dir_path: dir.path().to_path_buf(),
        base: dir.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".to_owned(),
    })
    .unwrap();
    let full_range = PageIndex::new(0)..PageIndex::new(11);
    let filter = BitVec::from_elem(
        (full_range.end.get() - full_range.start.get()) as usize,
        false,
    );
    // get_base_memory_instructions is exhaustive => empty get_memory_instructions.
    assert!(storage
        .get_memory_instructions(full_range.clone(), &mut filter.clone())
        .instructions
        .is_empty());
    assert!(!storage
        .get_base_memory_instructions()
        .instructions
        .is_empty());

    // Base files plus one overlay on top; some instructions needed beyond
    // get_base_memory_instructions.
    let dir = tempdir().unwrap();
    write_overlays_and_verify_with_tempdir(
        vec![
            WriteOverlay(vec![1, 10]),
            WriteOverlay(vec![5]),
            WriteOverlay(vec![5]),
        ],
        &lsmt_config_sharded(),
        &dir,
    );
    let storage = Storage::load(&ShardedTestStorageLayout {
        dir_path: dir.path().to_path_buf(),
        base: dir.path().join("vmemory_0.bin"),
        overlay_suffix: "vmemory_0.overlay".to_owned(),
    })
    .unwrap();
    assert!(!storage
        .get_memory_instructions(full_range, &mut filter.clone())
        .instructions
        .is_empty())
}

#[test]
fn overlapping_page_ranges() {
    let tempdir = tempdir().unwrap();
    // File indices:
    //  0  1  2  3   4   5   6   7   8    9    10   11   12
    let instructions = vec![WriteOverlay(vec![
        1, 2, 3, 10, 11, 12, 13, 20, 100, 101, 102, 110, 120,
    ])];

    fn page_index_range(start: u64, end: u64, file: u64) -> PageIndexRange {
        PageIndexRange {
            start_page: PageIndex::from(start),
            end_page: PageIndex::from(end),
            start_file_index: FileIndex::from(file),
        }
    }
    write_overlays_and_verify_with_tempdir(instructions, &lsmt_config_unsharded(), &tempdir);
    let storage_files = storage_files(tempdir.path());
    assert!(storage_files.base.is_none());
    assert_eq!(storage_files.overlays.len(), 1);
    let overlay = OverlayFile::load(&storage_files.overlays[0]).unwrap();
    let overlapped_ranges = overlay
        .get_overlapping_page_ranges(PageIndex::from(11)..PageIndex::from(102))
        .collect::<Vec<_>>();
    // Can clamp both first and last index, the start has clamped start_file_index.
    assert_eq!(
        overlapped_ranges,
        vec![
            page_index_range(11, 14, 4),
            page_index_range(20, 21, 7),
            page_index_range(100, 102, 8)
        ]
    );
    assert_eq!(
        overlay
            .get_overlapping_page_ranges(PageIndex::from(0)..PageIndex::from(1))
            .count(),
        0
    );
    assert_eq!(
        overlay
            .get_overlapping_page_ranges(PageIndex::from(21)..PageIndex::from(100))
            .count(),
        0
    );
}

#[cfg(not(feature = "fuzzing_code"))]
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
