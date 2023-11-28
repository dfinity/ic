use std::{
    fs::File,
    io::Write,
    os::{fd::FromRawFd, unix::prelude::FileExt},
    path::{Path, PathBuf},
};

use crate::page_map::{
    storage::{OverlayFile, Storage, INDEX_ENTRY_NUM_BYTES, SIZE_NUM_BYTES, VERSION_NUM_BYTES},
    FileDescriptor, MemoryInstructions, MemoryMapOrData, PageAllocator, PageDelta,
    PersistenceError, StorageMetrics,
};
use bit_vec::BitVec;
use ic_metrics::MetricsRegistry;
use ic_sys::{PageIndex, PAGE_SIZE};
use ic_test_utilities::io::{make_mutable, make_readonly, write_all_at};
use tempfile::{tempdir, TempDir};

/// The expected size of an overlay file.
///
/// The expectation is based on how many pages the overlay contains and how many distinct
/// ranges of indices there are.
fn expected_overlay_file_size(num_pages: u64, num_ranges: u64) -> u64 {
    let data = num_pages * PAGE_SIZE as u64;
    let index = num_ranges * INDEX_ENTRY_NUM_BYTES as u64;

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
        assert_eq!(overlay.get_page(index), expected.get_page(index));
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

/// Write the entire data from `delta` into a byte buffer.
fn page_delta_as_buffer(delta: &PageDelta) -> Vec<u8> {
    let mut result: Vec<u8> =
        vec![0; (delta.max_page_index().unwrap().get() as usize + 1) * PAGE_SIZE];
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

/// Base file and storage file in directory `dir`.
/// These tests use the schema where the base file is called `base.bin`,
/// and overlays end in `overlay`.
fn storage_files(dir: &Path) -> (PathBuf, Vec<PathBuf>) {
    let base_path = dir.join("base.bin");

    let mut overlays: Vec<PathBuf> = Default::default();
    for file in std::fs::read_dir(dir).unwrap() {
        let path = file.unwrap().path();
        if path.to_str().unwrap().ends_with("overlay") {
            overlays.push(path);
        }
    }
    overlays.sort();

    (base_path, overlays)
}

/// Verify that the storage in the `dir` directory is equivalent to `expected`.
fn verify_storage(dir: &Path, expected: &PageDelta) {
    let (base_path, overlays) = storage_files(dir);
    let base = if base_path.exists() {
        Some(base_path.as_path())
    } else {
        None
    };

    let storage = Storage::load(base, &overlays).unwrap();

    // Verify num_host_pages.
    assert_eq!(
        expected.max_page_index().unwrap().get() + 1,
        storage.num_logical_pages() as u64
    );

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

/// An instruction to modify a storage.
// TODO (IC-1306): Add Merge instruction
enum Instruction {
    WriteOverlay(Vec<u64>), // With list of PageIndex to overwrite.
}
use Instruction::*;

/// This function applies `instructions` to a new `Storage` in a temporary directory.
/// At the same time, we apply the same instructions, a `PageDelta`, which acts as the reference
/// implementation. After each operation, we check that all overlay files are as expected and
/// correspond to the reference.
fn write_overlays_and_verify_with_tempdir(instructions: Vec<Instruction>, tempdir: &TempDir) {
    let allocator = PageAllocator::new_for_testing();
    let metrics = StorageMetrics::new(&MetricsRegistry::new());

    let mut combined_delta = PageDelta::default();

    for (round, instruction) in instructions.iter().enumerate() {
        let path = &tempdir
            .path()
            .join(format!("{:06}_vmemory_0.overlay", round));
        match instruction {
            WriteOverlay(round_indices) => {
                let data = &[round as u8; PAGE_SIZE];
                let overlay_pages: Vec<_> = round_indices
                    .iter()
                    .map(|i| (PageIndex::new(*i), data))
                    .collect();

                let delta = PageDelta::from(allocator.allocate(&overlay_pages));

                OverlayFile::write(&delta, path, &metrics).unwrap();

                // Check both the file we just wrote and the resulting directory for correctness.
                verify_overlay_file(path, &delta);

                combined_delta.update(delta);

                verify_storage(tempdir.path(), &combined_delta);
            }
        }
    }
}

/// Apply a list of `Instruction` to a new tempory directory and check correctness of the sequence
/// after every step.
fn write_overlays_and_verify(instructions: Vec<Instruction>) {
    let tempdir = tempdir().unwrap();
    write_overlays_and_verify_with_tempdir(instructions, &tempdir);
}

#[test]
fn corrupt_overlay_is_an_error() {
    let tempdir = tempdir().unwrap();
    write_overlays_and_verify_with_tempdir(vec![WriteOverlay(vec![9, 10])], &tempdir);
    let files = storage_files(tempdir.path());
    assert!(files.1.len() == 1);
    let overlay_path = &files.1[0];
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
