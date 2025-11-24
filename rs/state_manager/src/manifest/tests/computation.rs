use crate::manifest::{
    BaseManifestInfo, ChunkAction, ChunkValidationError, DEFAULT_CHUNK_SIZE, DiffScript,
    FileWithSize, MAX_FILE_SIZE_TO_GROUP_V3, MAX_FILE_SIZE_TO_GROUP_V4, ManifestMetrics,
    ManifestValidationError, RehashManifest, StateSyncVersion, build_chunk_table_parallel,
    build_file_group_chunks, build_meta_manifest, compute_manifest, diff_manifest,
    file_chunk_range, files_with_same_inodes, files_with_sizes, filter_out_zero_chunks,
    hash::ManifestHash, hash_plan, manifest_hash, manifest_hash_v1, manifest_hash_v2,
    meta_manifest_hash, validate_chunk, validate_manifest, validate_manifest_internal_consistency,
    validate_meta_manifest, validate_sub_manifest,
};
use crate::state_sync::types::{
    ChunkInfo, FILE_GROUP_CHUNK_ID_OFFSET, FileGroupChunks, FileInfo, Manifest, MetaManifest,
    decode_manifest, encode_manifest,
};

use ic_crypto_sha2::Sha256;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_state_layout::{CANISTER_FILE, CheckpointLayout, UNVERIFIED_CHECKPOINT_MARKER};
use ic_test_utilities_tmpdir::tmpdir;
use ic_types::state_sync::CURRENT_STATE_SYNC_VERSION;
use ic_types::{CryptoHashOfState, Height, crypto::CryptoHash};
use maplit::btreeset;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, panic};
use strum::IntoEnumIterator;

const NUM_THREADS: u32 = 3;

macro_rules! hash_concat {
    ($( $x:expr_2021 ),*) => {
        {
            let mut h = Sha256::new();
            $( $x.update_hash(&mut h); )*
            h.finish()
        }
    }
}

fn file_hash(file_index: u32, chunks: &[&[u8]], version: StateSyncVersion) -> [u8; 32] {
    let mut h = Sha256::new();
    13u8.update_hash(&mut h);
    b"ic-state-file".update_hash(&mut h);
    (chunks.len() as u32).update_hash(&mut h);

    let mut offset = 0u64;
    for &chunk in chunks {
        if version < StateSyncVersion::V3 {
            // In versions before V3, the file hash includes the file index.
            file_index.update_hash(&mut h);
        }
        (chunk.len() as u32).update_hash(&mut h);
        offset.update_hash(&mut h);
        let chunk_hash = hash_concat!(14u8, b"ic-state-chunk", chunk);
        chunk_hash.update_hash(&mut h);
        offset += chunk.len() as u64;
    }
    h.finish()
}

fn simple_file_table_and_chunk_table(version: StateSyncVersion) -> (Vec<FileInfo>, Vec<ChunkInfo>) {
    assert!(version >= StateSyncVersion::V1);

    let chunk_0 = &[0u8; 1000];
    let chunk_1 = &[1u8; 1024];
    let chunk_2 = &[1u8; 1024];
    let chunk_3 = &[2u8; 1024];
    let chunk_4 = &[2u8; 26];
    let chunk_0_hash = hash_concat!(14u8, b"ic-state-chunk", chunk_0);
    let chunk_1_hash = hash_concat!(14u8, b"ic-state-chunk", chunk_1);
    let chunk_2_hash = hash_concat!(14u8, b"ic-state-chunk", chunk_2);
    let chunk_3_hash = hash_concat!(14u8, b"ic-state-chunk", chunk_3);
    let chunk_4_hash = hash_concat!(14u8, b"ic-state-chunk", chunk_4);

    let file_0_hash = file_hash(0, &[chunk_0], version);
    let file_1_hash = file_hash(1, &[chunk_1, chunk_2], version);
    let file_2_hash = file_hash(2, &[chunk_3, chunk_4], version);
    let file_3_hash = file_hash(3, &[], version);

    let file_table = vec![
        FileInfo {
            relative_path: "root.bin".into(),
            size_bytes: 1000,
            hash: file_0_hash,
        },
        FileInfo {
            relative_path: "subdir/memory".into(),
            size_bytes: 2048,
            hash: file_1_hash,
        },
        FileInfo {
            relative_path: "subdir/metadata".into(),
            size_bytes: 1050,
            hash: file_2_hash,
        },
        FileInfo {
            relative_path: "subdir/queue".into(),
            size_bytes: 0,
            hash: file_3_hash,
        },
    ];

    let chunk_table = vec![
        ChunkInfo {
            file_index: 0,
            size_bytes: 1000,
            offset: 0,
            hash: chunk_0_hash,
        },
        ChunkInfo {
            file_index: 1,
            size_bytes: 1024,
            offset: 0,
            hash: chunk_1_hash,
        },
        ChunkInfo {
            file_index: 1,
            size_bytes: 1024,
            offset: 1024,
            hash: chunk_2_hash,
        },
        ChunkInfo {
            file_index: 2,
            size_bytes: 1024,
            offset: 0,
            hash: chunk_3_hash,
        },
        ChunkInfo {
            file_index: 2,
            size_bytes: 26,
            offset: 1024,
            hash: chunk_4_hash,
        },
    ];

    (file_table, chunk_table)
}

// The file table and chunk table is used to create a manifest which is larger than 100 MiB after encoding.
pub(crate) fn dummy_file_table_and_chunk_table() -> (Vec<FileInfo>, Vec<ChunkInfo>) {
    let chunk_hash = hash_concat!(14u8, b"ic-state-chunk", vec![0u8; 1000].as_slice());
    let file_hash = hash_concat!(
        13u8,
        b"ic-state-file",
        1u32,
        0u32,
        1000u32,
        0u64,
        &chunk_hash[..]
    );
    let chunk_info = ChunkInfo {
        file_index: 0,
        size_bytes: 1000,
        offset: 0,
        hash: chunk_hash,
    };

    let file_info = FileInfo {
        relative_path: "root.bin".into(),
        size_bytes: 1000,
        hash: file_hash,
    };

    (vec![file_info; 1_000_000], vec![chunk_info; 3_000_000])
}

fn simple_manifest_v1() -> ([u8; 32], Manifest) {
    let (file_table, chunk_table) = simple_file_table_and_chunk_table(StateSyncVersion::V1);
    let manifest = Manifest::new(
        StateSyncVersion::V1,
        file_table.clone(),
        chunk_table.clone(),
    );
    let expected_hash = hash_concat!(
        17u8,
        b"ic-state-manifest",
        StateSyncVersion::V1,
        // files
        4u32,
        "root.bin",
        1000u64,
        &file_table[0].hash[..],
        "subdir/memory",
        2048u64,
        &file_table[1].hash[..],
        "subdir/metadata",
        1050u64,
        &file_table[2].hash[..],
        "subdir/queue",
        0u64,
        &file_table[3].hash[..],
        // chunks
        5u32,
        // chunk 0
        0u32,
        1000u32,
        0u64,
        &chunk_table[0].hash[..],
        // chunk 1
        1u32,
        1024u32,
        0u64,
        &chunk_table[1].hash[..],
        // chunk 2
        1u32,
        1024u32,
        1024u64,
        &chunk_table[2].hash[..],
        // chunk 3
        2u32,
        1024u32,
        0u64,
        &chunk_table[3].hash[..],
        // chunk 4
        2u32,
        26u32,
        1024u64,
        &chunk_table[4].hash[..]
    );

    (expected_hash, manifest)
}

/// Generates a valid manifest with version V2 or higher.
fn simple_manifest(version: StateSyncVersion) -> ([u8; 32], Manifest) {
    assert!(version >= StateSyncVersion::V2);

    let (file_table, chunk_table) = simple_file_table_and_chunk_table(version);
    let manifest = Manifest::new(version, file_table, chunk_table);
    let encoded_manifest = encode_manifest(&manifest);
    // The encoded bytes of the simple manifest is no greater than 1 MiB.
    // If it is not the case due to future changes, the `sub_manifest_hash` below should also be updated.
    assert!(encoded_manifest.len() <= DEFAULT_CHUNK_SIZE as usize);

    let sub_manifest_hash = hash_concat!(21u8, b"ic-state-sub-manifest", &encoded_manifest[..]);
    let expected_hash = hash_concat!(
        22u8,
        b"ic-state-meta-manifest",
        version,
        1u32,
        &sub_manifest_hash[..]
    );
    (expected_hash, manifest)
}

/// Returns an iterator over versions between `start_inclusive` and
/// `CURRENT_STATE_SYNC_VERSION` (both inclusive).
fn versions_from(start_inclusive: StateSyncVersion) -> impl Iterator<Item = StateSyncVersion> {
    StateSyncVersion::iter()
        .skip_while(move |v| *v < start_inclusive)
        .take_while(move |v| *v <= CURRENT_STATE_SYNC_VERSION)
}

/// A list of manifests with hashes of all supported versions
/// that will be used in tests related to the manifest hash.
fn simple_manifest_all_supported_versions() -> Vec<([u8; 32], Manifest)> {
    let manifests = vec![
        simple_manifest_v1(),
        simple_manifest(StateSyncVersion::V2),
        simple_manifest(StateSyncVersion::V3),
    ];
    // Sanity check: ensure that we have one manifest for every supported version.
    assert_eq!(
        manifests.iter().map(|(_, m)| m.version).collect::<Vec<_>>(),
        versions_from(StateSyncVersion::V1).collect::<Vec<_>>(),
        "One manifest must be provided for every supported version."
    );
    manifests
}

#[test]
fn test_simple_manifest_computation() {
    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    let dir = tempfile::TempDir::new().expect("failed to create a temporary directory");

    let root = dir.path();
    fs::write(root.join("root.bin"), vec![0u8; 1000]).expect("failed to create file 'test.bin'");

    let subdir = root.join("subdir");
    fs::create_dir_all(&subdir).expect("failed to create dir 'subdir'");
    fs::write(subdir.join("memory"), vec![1u8; 2048]).expect("failed to create file 'memory'");
    fs::write(subdir.join("queue"), vec![0u8; 0]).expect("failed to create file 'queue'");
    fs::write(subdir.join("metadata"), vec![2u8; 1050]).expect("failed to create file 'queue'");

    let test_computation_with_num_threads = |num_threads: u32| {
        let mut thread_pool = scoped_threadpool::Pool::new(num_threads);
        let manifest_v1 = compute_manifest(
            &mut thread_pool,
            &manifest_metrics,
            &no_op_logger(),
            StateSyncVersion::V1,
            &CheckpointLayout::new_untracked(root.to_path_buf(), Height::new(0)).unwrap(),
            1024,
            None,
            RehashManifest::No,
        )
        .expect("failed to compute manifest");

        let (expected_hash, expected_manifest) = simple_manifest_v1();
        assert_eq!(manifest_v1, expected_manifest);
        assert_eq!(expected_hash, manifest_hash_v1(&manifest_v1));
        assert_eq!(expected_hash, manifest_hash(&manifest_v1));

        for version in versions_from(StateSyncVersion::V2) {
            let manifest = compute_manifest(
                &mut thread_pool,
                &manifest_metrics,
                &no_op_logger(),
                version,
                &CheckpointLayout::new_untracked(root.to_path_buf(), Height::new(0)).unwrap(),
                1024,
                None,
                RehashManifest::No,
            )
            .expect("failed to compute manifest");

            let (expected_hash, expected_manifest) = simple_manifest(version);
            assert_eq!(manifest, expected_manifest);
            assert_eq!(expected_hash, manifest_hash_v2(&manifest));
            assert_eq!(expected_hash, manifest_hash(&manifest));
        }
    };

    for num_threads in 1..32u32 {
        test_computation_with_num_threads(num_threads)
    }
}

#[test]
fn test_manifest_computation_skips_marker_file() {
    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    let dir = tempfile::TempDir::new().expect("failed to create a temporary directory");

    let root = dir.path();
    fs::write(root.join("root.bin"), vec![0u8; 1000]).expect("failed to create file 'test.bin'");
    fs::File::create(root.join(UNVERIFIED_CHECKPOINT_MARKER))
        .expect("failed to create marker file");

    let subdir = root.join("subdir");
    fs::create_dir_all(&subdir).expect("failed to create dir 'subdir'");
    fs::write(subdir.join("memory"), vec![1u8; 2048]).expect("failed to create file 'memory'");
    fs::write(subdir.join("queue"), vec![0u8; 0]).expect("failed to create file 'queue'");
    fs::write(subdir.join("metadata"), vec![2u8; 1050]).expect("failed to create file 'queue'");

    let mut thread_pool = scoped_threadpool::Pool::new(1);

    let manifest_with_marker_present = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        StateSyncVersion::V1,
        &CheckpointLayout::new_untracked(root.to_path_buf(), Height::new(0)).unwrap(),
        1024,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");

    fs::remove_file(root.join(UNVERIFIED_CHECKPOINT_MARKER)).expect("failed to remove marker file");

    let manifest_with_marker_removed = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        StateSyncVersion::V1,
        &CheckpointLayout::new_untracked(root.to_path_buf(), Height::new(0)).unwrap(),
        1024,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");
    // The manifest computation should ignore the marker files and produce identical manifest.
    assert_eq!(manifest_with_marker_present, manifest_with_marker_removed);
}

#[test]
fn test_meta_manifest_computation() {
    for version in versions_from(StateSyncVersion::V2) {
        let (file_table, chunk_table) = simple_file_table_and_chunk_table(version);
        let manifest = Manifest::new(version, file_table, chunk_table);
        let meta_manifest = build_meta_manifest(&manifest);
        let encoded_manifest = encode_manifest(&manifest);
        assert!(encoded_manifest.len() <= DEFAULT_CHUNK_SIZE as usize);

        let sub_manifest_hash = hash_concat!(21u8, b"ic-state-sub-manifest", &encoded_manifest[..]);
        let expected_meta_manifest = MetaManifest {
            version,
            sub_manifest_hashes: vec![sub_manifest_hash],
        };

        assert_eq!(expected_meta_manifest, meta_manifest)
    }
}

#[test]
fn test_validate_sub_manifest() {
    let (file_table, chunk_table) = dummy_file_table_and_chunk_table();
    let manifest = Manifest::new(CURRENT_STATE_SYNC_VERSION, file_table, chunk_table);
    let meta_manifest = build_meta_manifest(&manifest);

    let encoded_manifest = encode_manifest(&manifest);
    let num = encoded_manifest.len().div_ceil(DEFAULT_CHUNK_SIZE as usize);
    assert!(
        num > 1,
        "This test does not cover the case where the encoded manifest is divided into multiple pieces."
    );
    let mut validated_bytes = 0;
    for ix in 0..num {
        let start = ix * DEFAULT_CHUNK_SIZE as usize;
        let end = std::cmp::min(start + DEFAULT_CHUNK_SIZE as usize, encoded_manifest.len());
        validated_bytes += end - start;
        assert_eq!(
            Ok(()),
            validate_sub_manifest(ix, &encoded_manifest[start..end], &meta_manifest)
        );
    }
    assert_eq!(
        validated_bytes,
        encoded_manifest.len(),
        "Not all bytes of the encoded manifest have been validated."
    );

    // Test that the provided chunk is out of the range of sub-manifests.
    assert_eq!(
        Err(ChunkValidationError::InvalidChunkIndex {
            chunk_ix: 159,
            actual_length: 159
        }),
        validate_sub_manifest(num, &[], &meta_manifest)
    );

    // Test that an altered chunk gives a different hash.
    let sub_manifest_0 = encoded_manifest
        [0..std::cmp::min(DEFAULT_CHUNK_SIZE as usize, encoded_manifest.len())]
        .to_vec();
    let expected_hash = hash_concat!(21u8, b"ic-state-sub-manifest", &sub_manifest_0[..]);
    assert_eq!(expected_hash, meta_manifest.sub_manifest_hashes[0]);

    let mut bad_chunk = sub_manifest_0;
    let alter_position = bad_chunk.len() / 2;
    bad_chunk[alter_position] = bad_chunk[alter_position].wrapping_add(1);
    let actual_hash = hash_concat!(21u8, b"ic-state-sub-manifest", &bad_chunk[..]);

    assert_eq!(
        Err(ChunkValidationError::InvalidChunkHash {
            chunk_ix: 0,
            expected_hash: expected_hash.to_vec(),
            actual_hash: actual_hash.to_vec()
        }),
        validate_sub_manifest(0, &bad_chunk, &meta_manifest)
    );
}

#[test]
fn test_get_sub_manifest_based_on_index() {
    let (file_table, chunk_table) = dummy_file_table_and_chunk_table();
    let manifest = Manifest::new(CURRENT_STATE_SYNC_VERSION, file_table, chunk_table);
    let meta_manifest = build_meta_manifest(&manifest);
    let encoded_manifest = encode_manifest(&manifest);

    let mut assembled_manifest = Vec::new();

    // For each element in the meta-manifest, we can get a corresponding sub-manifest as part of the manifest.
    let len = meta_manifest.sub_manifest_hashes.len();
    for index in 0..len {
        // The same way that `StateSyncMessage` uses to serve a sub-manifest in state sync.
        let start = index * DEFAULT_CHUNK_SIZE as usize;
        let end = std::cmp::min(start + DEFAULT_CHUNK_SIZE as usize, encoded_manifest.len());
        let sub_manifest = encoded_manifest
            .get(start..end)
            .expect("failed to get the sub-manifest")
            .to_vec();
        assembled_manifest.extend(sub_manifest);
    }
    assert_eq!(assembled_manifest, encoded_manifest);

    // Test that we get nothing given an out-of-bound index.
    let start = len * DEFAULT_CHUNK_SIZE as usize;
    let end = std::cmp::min(start + DEFAULT_CHUNK_SIZE as usize, encoded_manifest.len());
    assert!(encoded_manifest.get(start..end).is_none());
}

#[test]
fn simple_manifest_passes_validation() {
    for (expected_hash, manifest) in simple_manifest_all_supported_versions() {
        assert_eq!(Ok(()), validate_manifest_internal_consistency(&manifest));
        assert_eq!(
            Ok(()),
            validate_manifest(
                &manifest,
                &CryptoHashOfState::from(CryptoHash(expected_hash.to_vec()))
            )
        );
    }
}

#[test]
fn meta_manifest_passes_validation() {
    for version in versions_from(StateSyncVersion::V2) {
        let (file_table, chunk_table) = simple_file_table_and_chunk_table(version);
        let manifest = Manifest::new(version, file_table, chunk_table);
        let meta_manifest = build_meta_manifest(&manifest);
        assert_eq!(
            Ok(()),
            validate_meta_manifest(
                &meta_manifest,
                &CryptoHashOfState::from(CryptoHash(meta_manifest_hash(&meta_manifest).to_vec()))
            )
        );
    }
}

#[test]
fn bad_root_hash_detected_for_meta_manifest() {
    for version in versions_from(StateSyncVersion::V2) {
        let bogus_hash = CryptoHashOfState::from(CryptoHash(vec![1u8; 32]));
        let (file_table, chunk_table) = simple_file_table_and_chunk_table(version);
        let manifest = Manifest::new(version, file_table, chunk_table);
        let meta_manifest = build_meta_manifest(&manifest);
        assert_eq!(
            validate_meta_manifest(&meta_manifest, &bogus_hash),
            Err(ManifestValidationError::InvalidRootHash {
                expected_hash: bogus_hash.get_ref().0.clone(),
                actual_hash: meta_manifest_hash(&meta_manifest).to_vec(),
            })
        );
    }
}

#[test]
fn bad_root_hash_detected() {
    let bogus_hash = CryptoHashOfState::from(CryptoHash(vec![1u8; 32]));
    for (manifest_hash, manifest) in simple_manifest_all_supported_versions() {
        // Manifest is internally consistent
        assert_eq!(Ok(()), validate_manifest_internal_consistency(&manifest));
        // But the hash does not match `bogus_hash`.
        assert_eq!(
            validate_manifest(&manifest, &bogus_hash),
            Err(ManifestValidationError::InvalidRootHash {
                expected_hash: bogus_hash.get_ref().0.clone(),
                actual_hash: manifest_hash.to_vec(),
            })
        );
    }
}

#[test]
fn bad_file_hash_detected() {
    for (manifest_hash, manifest) in simple_manifest_all_supported_versions() {
        let actual_hash = manifest.file_table[0].hash.to_vec();
        let mut file_table = manifest.file_table.to_owned();
        file_table[0].hash = [1u8; 32];
        let manifest = Manifest::new(
            manifest.version,
            file_table,
            manifest.chunk_table.to_owned(),
        );
        let root_hash = CryptoHashOfState::from(CryptoHash(manifest_hash.to_vec()));

        assert_eq!(
            validate_manifest_internal_consistency(&manifest),
            Err(ManifestValidationError::InvalidFileHash {
                relative_path: manifest.file_table[0].relative_path.clone(),
                expected_hash: vec![1u8; 32],
                actual_hash: actual_hash.clone(),
            })
        );
        assert_eq!(
            validate_manifest(&manifest, &root_hash),
            Err(ManifestValidationError::InvalidFileHash {
                relative_path: manifest.file_table[0].relative_path.clone(),
                expected_hash: vec![1u8; 32],
                actual_hash,
            })
        );
    }
}

#[test]
fn bad_chunk_size_detected() {
    for (_, manifest) in simple_manifest_all_supported_versions() {
        let chunk_0_size = manifest.chunk_table[0].size_bytes;
        let bad_chunk_size = chunk_0_size + 1;
        let bad_chunk = vec![0; bad_chunk_size as usize];
        assert_eq!(
            validate_chunk(0, &bad_chunk, &manifest),
            Err(ChunkValidationError::InvalidChunkSize {
                chunk_ix: 0,
                expected_size: chunk_0_size as usize,
                actual_size: bad_chunk_size as usize,
            })
        );
    }
}

#[test]
fn bad_chunk_hash_detected() {
    for (_, manifest) in simple_manifest_all_supported_versions() {
        let valid_chunk_0 = vec![0u8; 1000];
        assert_eq!(
            hash_concat!(14u8, b"ic-state-chunk", &valid_chunk_0[..]),
            manifest.chunk_table[0].hash
        );

        let mut bad_chunk = valid_chunk_0;
        bad_chunk[0] = 1;
        let actual_hash = hash_concat!(14u8, b"ic-state-chunk", &bad_chunk[..]);
        assert_eq!(
            validate_chunk(0, &bad_chunk, &manifest),
            Err(ChunkValidationError::InvalidChunkHash {
                chunk_ix: 0,
                expected_hash: manifest.chunk_table[0].hash.to_vec(),
                actual_hash: actual_hash.to_vec()
            })
        );
    }
}

#[test]
fn orphan_chunk_detected() {
    for (manifest_hash, manifest) in simple_manifest_all_supported_versions() {
        let mut chunk_table = manifest.chunk_table.to_owned();
        chunk_table.push(ChunkInfo {
            file_index: 100,
            size_bytes: 100,
            offset: 0,
            hash: [0; 32],
        });
        let manifest = Manifest::new(
            manifest.version,
            manifest.file_table.to_owned(),
            chunk_table,
        );
        let root_hash = CryptoHashOfState::from(CryptoHash(manifest_hash.to_vec()));

        match validate_manifest_internal_consistency(&manifest) {
            Err(ManifestValidationError::InconsistentManifest { .. }) => (),
            other => panic!("Expected an orphan chunk to be detected, got: {other:?}"),
        }
        match validate_manifest(&manifest, &root_hash) {
            Err(ManifestValidationError::InconsistentManifest { .. }) => (),
            other => panic!("Expected an orphan chunk to be detected, got: {other:?}"),
        }
    }
}

#[test]
fn test_diff_manifest_v1() {
    let (_, manifest_old) = simple_manifest_v1();
    let manifest_new = manifest_old.clone();
    let len = manifest_new.file_table.len();
    let indices = (0..len).collect::<Vec<usize>>();
    let hardlink_files: HashMap<_, _> = indices.clone().into_iter().zip(indices).collect();
    assert_eq!(
        diff_manifest(&manifest_old, &Default::default(), &manifest_new),
        DiffScript {
            hardlink_files,
            copy_chunks: Default::default(),
            fetch_chunks: Default::default(),
            zeros_chunks: 0,
        }
    );

    // the chunk_2 from the file_1 changes.
    let chunk_1_hash = hash_concat!(14u8, b"ic-state-chunk", vec![1u8; 1024].as_slice());
    let chunk_2_hash = hash_concat!(14u8, b"ic-state-chunk", vec![255u8; 1024].as_slice());
    let file_1_hash = hash_concat!(
        13u8,
        b"ic-state-file",
        2u32,
        1u32,
        1024u32,
        0u64,
        &chunk_1_hash[..],
        1u32,
        1024u32,
        1024u64,
        &chunk_2_hash[..]
    );

    let mut file_table = manifest_new.file_table.to_owned();
    file_table[1] = FileInfo {
        relative_path: "subdir/memory".into(),
        size_bytes: 2048,
        hash: file_1_hash,
    };

    let mut chunk_table = manifest_new.chunk_table.to_owned();
    chunk_table[2] = ChunkInfo {
        file_index: 1,
        size_bytes: 1024,
        offset: 1024,
        hash: chunk_2_hash,
    };

    let manifest_new = Manifest::new(manifest_new.version, file_table, chunk_table);

    let hardlink_files: HashMap<usize, usize> = maplit::hashmap! {
        0 => 0,
        2 => 2,
        3 => 3,
    };

    let copy_chunks: HashMap<usize, usize> = maplit::hashmap! {
        1 => 2,
    };

    let fetch_chunks: HashSet<usize> = maplit::hashset! {2};

    assert_eq!(
        diff_manifest(&manifest_old, &Default::default(), &manifest_new),
        DiffScript {
            hardlink_files,
            copy_chunks,
            fetch_chunks,
            zeros_chunks: 0,
        }
    );
}

#[test]
fn test_diff_manifest() {
    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    let dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let root = dir.path();

    fs::write(root.join("root.bin"), vec![2u8; 1000 * 1024])
        .expect("failed to create file 'test.bin'");

    let subdir = root.join("subdir");
    fs::create_dir_all(&subdir).expect("failed to create dir 'subdir'");
    fs::write(subdir.join("memory"), vec![1u8; 2048 * 1024])
        .expect("failed to create file 'memory'");
    fs::write(subdir.join("metadata"), vec![3u8; 1050 * 1024])
        .expect("failed to create file 'metadata'");
    fs::write(subdir.join("queue"), vec![0u8; 0]).expect("failed to create file 'queue'");

    let mut thread_pool = scoped_threadpool::Pool::new(NUM_THREADS);
    let manifest_old = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        CURRENT_STATE_SYNC_VERSION,
        &CheckpointLayout::new_untracked(root.to_path_buf(), Height::new(0)).unwrap(),
        1024 * 1024,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");

    fs::write(subdir.join("metadata"), vec![3u8; 2048 * 1024])
        .expect("failed to write file 'metadata'");
    fs::write(subdir.join("queue"), vec![0u8; 2048 * 1024]).expect("failed to write file 'queue'");
    // The files in the manifest is sorted by relative path. The index of file
    // 'metadata' is 2. The indices of its chunks are 3 and 4.
    let manifest_new = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        CURRENT_STATE_SYNC_VERSION,
        &CheckpointLayout::new_untracked(root.to_path_buf(), Height::new(0)).unwrap(),
        1024 * 1024,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");

    let hardlink_files: HashMap<usize, usize> = maplit::hashmap! {
        0 => 0,
        1 => 1,
    };

    // chunk_4 does change but it is the same as the original chunk_3.
    let copy_chunks: HashMap<usize, usize> = maplit::hashmap! {
        3 => 3,
        4 => 3,
    };

    assert_eq!(
        diff_manifest(&manifest_old, &Default::default(), &manifest_new),
        DiffScript {
            hardlink_files,
            copy_chunks,
            fetch_chunks: Default::default(),
            zeros_chunks: 2,
        }
    );
}

#[test]
fn test_filter_all_zero_chunks() {
    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    let dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let root = dir.path();

    fs::write(root.join("root.bin"), vec![2u8; 1000 * 1024])
        .expect("failed to create file 'test.bin'");

    let subdir = root.join("subdir");
    fs::create_dir_all(&subdir).expect("failed to create dir 'subdir'");
    fs::write(subdir.join("memory"), vec![0u8; 2048 * 1024])
        .expect("failed to create file 'memory'");
    fs::write(subdir.join("metadata"), vec![3u8; 1050 * 1024])
        .expect("failed to create file 'metadata'");
    fs::write(subdir.join("queue"), vec![0u8; 1050 * 1024]).expect("failed to create file 'queue'");

    let mut thread_pool = scoped_threadpool::Pool::new(NUM_THREADS);
    let manifest = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        CURRENT_STATE_SYNC_VERSION,
        &CheckpointLayout::new_untracked(root.to_path_buf(), Height::new(0)).unwrap(),
        1024 * 1024,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");

    let fetch_chunks: HashSet<usize> = maplit::hashset! {0, 3, 4, 6};

    assert_eq!(filter_out_zero_chunks(&manifest), fetch_chunks);
}

#[test]
fn test_missing_simple_manifest() {
    let (_, manifest_old) = simple_manifest(CURRENT_STATE_SYNC_VERSION);
    let manifest_new = manifest_old.clone();
    let len = manifest_new.file_table.len();
    let indices = (0..len).collect::<Vec<usize>>();
    let hardlink_files: HashMap<_, _> = indices.clone().into_iter().zip(indices).collect();
    assert_eq!(
        diff_manifest(&manifest_old, &Default::default(), &manifest_new),
        DiffScript {
            hardlink_files,
            copy_chunks: Default::default(),
            fetch_chunks: Default::default(),
            zeros_chunks: 0,
        }
    );

    // the chunk_2 from the file_1 is marked as missing, but chunk_1 is the same as
    // chunk_2
    let missing_chunks = maplit::hashset! {2};

    assert_eq!(
        diff_manifest(&manifest_old, &missing_chunks, &manifest_new),
        DiffScript {
            hardlink_files: maplit::hashmap! {
                0 => 0,
                2 => 2,
                3 => 3,
            },
            copy_chunks: maplit::hashmap! {
                1 => 1, 2 => 1,
            },
            fetch_chunks: Default::default(),
            zeros_chunks: 0,
        }
    );

    // both chunk_1 and chunk_2 from file_1 are missing, need to be fetched
    let missing_chunks = maplit::hashset! {1, 2};

    assert_eq!(
        diff_manifest(&manifest_old, &missing_chunks, &manifest_new),
        DiffScript {
            hardlink_files: maplit::hashmap! {
                0 => 0,
                2 => 2,
                3 => 3,
            },
            copy_chunks: Default::default(),
            // Even though chunks 1 and 2 have the same hash, we do not handle this case and
            // simply ask to fetch both independently
            fetch_chunks: maplit::hashset! {1, 2},
            zeros_chunks: 0,
        }
    );
}

#[test]
fn test_simple_manifest_encoding_roundtrip() {
    let (_hash, manifest) = simple_manifest_v1();
    assert_eq!(
        decode_manifest(&encode_manifest(&manifest)[..]),
        Ok(manifest)
    );

    for version in versions_from(StateSyncVersion::V2) {
        let (_hash, manifest) = simple_manifest(version);
        assert_eq!(
            decode_manifest(&encode_manifest(&manifest)[..]),
            Ok(manifest)
        );
    }
}

#[test]
fn test_hash_plan() {
    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    let dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let base_dir = dir.path().join("base");
    let populate_checkpoint = |root: &Path| {
        fs::create_dir_all(root).unwrap();

        fs::write(root.join("root.bin"), vec![2u8; 1000 * 1024])
            .expect("failed to create file 'root.bin'");

        let subdir = root.join("subdir");
        fs::create_dir_all(&subdir).expect("failed to create dir 'subdir'");

        fs::write(subdir.join("memory"), vec![1u8; 2048 * 1024])
            .expect("failed to create file 'memory'");

        fs::write(subdir.join("metadata"), vec![3u8; 1050 * 1024])
            .expect("failed to create file 'metadata'");
    };
    populate_checkpoint(&base_dir);
    let max_chunk_size = 1024 * 1024;

    let mut thread_pool = scoped_threadpool::Pool::new(NUM_THREADS);
    let manifest_old = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        CURRENT_STATE_SYNC_VERSION,
        &CheckpointLayout::new_untracked(base_dir.to_path_buf(), Height::new(0)).unwrap(),
        max_chunk_size,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");

    let next_dir = dir.path().join("next");
    populate_checkpoint(&next_dir);
    let mut memory_new = vec![1u8; 1024 * 1024];
    memory_new.append(&mut vec![6u8; 2048 * 1024]);

    fs::write(next_dir.join("subdir").join("memory"), memory_new)
        .expect("failed to write file 'memory'");

    // Compute the manifest from scratch.
    let manifest_new = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        CURRENT_STATE_SYNC_VERSION,
        &CheckpointLayout::new_untracked(next_dir.to_path_buf(), Height::new(0)).unwrap(),
        max_chunk_size,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");

    // Compute the manifest incrementally.
    let mut files = files_with_sizes(&next_dir, "".into(), &mut thread_pool)
        .expect("failed to traverse the files");
    // We sort the table to make sure that the table is the same on all replicas
    files.sort_unstable_by(|lhs, rhs| lhs.0.cmp(&rhs.0));

    let files_with_same_inodes = btreeset! {
        PathBuf::from("root.bin"),
    };

    let build_manifest_from_hash_plan = |hash_plan| {
        let mut thread_pool = scoped_threadpool::Pool::new(NUM_THREADS);
        let (file_table, chunk_table) = build_chunk_table_parallel(
            &mut thread_pool,
            &manifest_metrics,
            &no_op_logger(),
            &next_dir,
            files.clone(),
            max_chunk_size,
            hash_plan,
            CURRENT_STATE_SYNC_VERSION,
        );

        Manifest::new(CURRENT_STATE_SYNC_VERSION, file_table, chunk_table)
    };

    // Hash plan with recompute_period == 1
    let chunk_actions = hash_plan(
        &manifest_old,
        &files,
        files_with_same_inodes.clone(),
        max_chunk_size,
        0,
        1,
    );

    assert_eq!(
        chunk_actions,
        vec![
            ChunkAction::RecomputeAndCompare(manifest_old.chunk_table[0].hash),
            ChunkAction::Recompute,
            ChunkAction::Recompute,
            ChunkAction::Recompute,
            ChunkAction::Recompute,
            ChunkAction::Recompute
        ]
    );

    let incremental_manifest = build_manifest_from_hash_plan(chunk_actions);

    assert_eq!(manifest_new, incremental_manifest);

    // Hash plan with recompute_period == 0
    let chunk_actions = hash_plan(
        &manifest_old,
        &files,
        files_with_same_inodes.clone(),
        max_chunk_size,
        0,
        u64::MAX,
    );

    assert_eq!(
        chunk_actions,
        vec![
            ChunkAction::UseHash(manifest_old.chunk_table[0].hash),
            ChunkAction::Recompute,
            ChunkAction::Recompute,
            ChunkAction::Recompute,
            ChunkAction::Recompute,
            ChunkAction::Recompute
        ]
    );

    let incremental_manifest = build_manifest_from_hash_plan(chunk_actions);

    assert_eq!(manifest_new, incremental_manifest);

    // Hash plan with recompute_period == 2
    // We loop several times and check that we recompute the chunk between 40% and
    // 60%
    let repetitions = 1000;
    let mut seen_used = 0;
    for seed in 0..repetitions {
        let chunk_actions = hash_plan(
            &manifest_old,
            &files,
            files_with_same_inodes.clone(),
            max_chunk_size,
            seed,
            2,
        );

        // It's random, so there could be two possible hash plans
        if let ChunkAction::UseHash(_) = chunk_actions[0] {
            seen_used += 1;
            assert_eq!(
                chunk_actions,
                vec![
                    ChunkAction::UseHash(manifest_old.chunk_table[0].hash),
                    ChunkAction::Recompute,
                    ChunkAction::Recompute,
                    ChunkAction::Recompute,
                    ChunkAction::Recompute,
                    ChunkAction::Recompute
                ]
            );
        } else {
            assert_eq!(
                chunk_actions,
                vec![
                    ChunkAction::RecomputeAndCompare(manifest_old.chunk_table[0].hash),
                    ChunkAction::Recompute,
                    ChunkAction::Recompute,
                    ChunkAction::Recompute,
                    ChunkAction::Recompute,
                    ChunkAction::Recompute
                ]
            );
        }

        let incremental_manifest = build_manifest_from_hash_plan(chunk_actions);

        assert_eq!(manifest_new, incremental_manifest);
    }
    assert!(seen_used as f64 >= 0.4 * repetitions as f64);
    assert!(seen_used as f64 <= 0.6 * repetitions as f64);
}

#[test]
fn test_files_with_same_inodes() {
    let dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let root = dir.path();
    let checkpoint0 = root.join("checkpoint0");
    fs::create_dir(&checkpoint0).expect("failed to create dir 'subdir'");
    let checkpoint1 = root.join("checkpoint1");
    fs::create_dir(&checkpoint1).expect("failed to create dir 'subdir'");

    fs::write(checkpoint0.join("wasm_a"), vec![1u8; 2048 * 1024])
        .expect("failed to create file 'wasm_a'");
    fs::write(checkpoint0.join("wasm_b"), vec![1u8; 2048 * 1024])
        .expect("failed to create file 'wasm_b'");
    fs::write(checkpoint1.join("wasm_a"), vec![1u8; 2048 * 1024])
        .expect("failed to create file 'wasm_a'");
    fs::hard_link(checkpoint0.join("wasm_b"), checkpoint1.join("wasm_b"))
        .expect("failed to hardlink wasm_b");

    let max_chunk_size = 1024 * 1024;

    let mut thread_pool = scoped_threadpool::Pool::new(NUM_THREADS);
    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    let base_manifest = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        CURRENT_STATE_SYNC_VERSION,
        &CheckpointLayout::new_untracked(checkpoint0.to_path_buf(), Height::new(0)).unwrap(),
        max_chunk_size,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");
    let files_with_same_inodes = files_with_same_inodes(
        &no_op_logger(),
        &BaseManifestInfo {
            base_manifest,
            base_height: Height::new(0),
            target_height: Height::new(1),
            base_checkpoint: CheckpointLayout::new_untracked(
                checkpoint0.to_path_buf(),
                Height::new(0),
            )
            .unwrap(),
        },
        &CheckpointLayout::new_untracked(checkpoint1.to_path_buf(), Height::new(1)).unwrap(),
        &[
            FileWithSize("wasm_a".into(), 2048 * 1024),
            FileWithSize("wasm_b".into(), 2048 * 1024),
        ],
        max_chunk_size,
        &mut thread_pool,
    );
    assert_eq!(
        files_with_same_inodes,
        btreeset! {
            PathBuf::from("wasm_b"),
        }
    );
}

#[test]
fn test_file_chunk_range() {
    let manifest = simple_manifest(CURRENT_STATE_SYNC_VERSION).1;
    for file_index in 0..manifest.file_table.len() {
        let range = file_chunk_range(&manifest.chunk_table, file_index);

        // Size of file == sum of size of chunks
        assert_eq!(
            manifest.file_table[file_index].size_bytes,
            range
                .map(|chunk_index| manifest.chunk_table[chunk_index].size_bytes as u64)
                .sum::<u64>()
        );
    }
}

#[test]
fn test_build_file_group_chunks() {
    let dummy_file_hash = [0u8; 32];
    let dummy_chunk_hash = [0u8; 32];
    let file_group_file_info = |id: u32| -> FileInfo {
        FileInfo {
            relative_path: std::path::PathBuf::from(id.to_string()).join(CANISTER_FILE),
            size_bytes: 500,
            hash: dummy_file_hash,
        }
    };

    let normal_file_info = |id: u32| -> Vec<FileInfo> {
        vec![
            FileInfo {
                relative_path: std::path::PathBuf::from(id.to_string()).join("software.wasm"),
                size_bytes: 500,
                hash: dummy_file_hash,
            },
            FileInfo {
                relative_path: std::path::PathBuf::from(id.to_string()).join("vmemory_0.bin"),
                size_bytes: DEFAULT_CHUNK_SIZE as u64 + 500,
                hash: dummy_file_hash,
            },
        ]
    };

    let file_group_chunk_info = |id: u32| -> ChunkInfo {
        ChunkInfo {
            file_index: 3 * id,
            size_bytes: 500,
            offset: 0,
            hash: dummy_chunk_hash,
        }
    };

    let normal_chunk_info = |id: u32| -> Vec<ChunkInfo> {
        vec![
            ChunkInfo {
                file_index: 3 * id + 1,
                size_bytes: 500,
                offset: 0,
                hash: dummy_chunk_hash,
            },
            ChunkInfo {
                file_index: 3 * id + 2,
                size_bytes: DEFAULT_CHUNK_SIZE,
                offset: 0,
                hash: dummy_chunk_hash,
            },
            ChunkInfo {
                file_index: 3 * id + 2,
                size_bytes: 500,
                offset: DEFAULT_CHUNK_SIZE as u64,
                hash: dummy_chunk_hash,
            },
        ]
    };

    let mut file_table = Vec::new();
    let mut chunk_table = Vec::new();
    let total_num = 10_000;
    for id in 0..total_num {
        file_table.push(file_group_file_info(id));
        file_table.extend(normal_file_info(id));
        chunk_table.push(file_group_chunk_info(id));
        chunk_table.extend(normal_chunk_info(id))
    }

    // A "canister.pbuf" file larger than `MAX_FILE_SIZE_TO_GROUP_V3` bytes will not be grouped when using V3 manifest.
    // However, since it is smaller than `MAX_FILE_SIZE_TO_GROUP_V4`, it will be grouped when using V4 manifest.
    let medium_file_index = file_table.len() as u32;
    let medium_chunk_index = chunk_table.len() as u32;
    file_table.push(FileInfo {
        relative_path: std::path::PathBuf::from(medium_file_index.to_string()).join(CANISTER_FILE),
        size_bytes: MAX_FILE_SIZE_TO_GROUP_V3 as u64 + 1,
        hash: dummy_file_hash,
    });
    chunk_table.push(ChunkInfo {
        file_index: medium_file_index,
        size_bytes: MAX_FILE_SIZE_TO_GROUP_V3 + 1,
        offset: 0,
        hash: dummy_chunk_hash,
    });

    // A "canister.pbuf" file larger than `MAX_FILE_SIZE_TO_GROUP_V4` bytes will not be grouped when using V4 manifest.
    let large_file_index = file_table.len() as u32;
    file_table.push(FileInfo {
        relative_path: std::path::PathBuf::from(large_file_index.to_string()).join(CANISTER_FILE),
        size_bytes: MAX_FILE_SIZE_TO_GROUP_V4 as u64 + 1,
        hash: dummy_file_hash,
    });
    chunk_table.push(ChunkInfo {
        file_index: large_file_index,
        size_bytes: MAX_FILE_SIZE_TO_GROUP_V4 + 1,
        offset: 0,
        hash: dummy_chunk_hash,
    });

    let manifest = Manifest::new(
        StateSyncVersion::V3,
        file_table.clone(),
        chunk_table.clone(),
    );
    let computed_file_group_chunks = build_file_group_chunks(&manifest);

    // Each chunk is expected to have 2097 files in it. Note: floor(1MiB / 500B) = 2097
    let indices_0: Vec<u32> = (0..2097).map(|i| i * 4).collect();
    let indices_1: Vec<u32> = (2097..2097 * 2).map(|i| i * 4).collect();
    let indices_2: Vec<u32> = (2097 * 2..2097 * 3).map(|i| i * 4).collect();
    let indices_3: Vec<u32> = (2097 * 3..2097 * 4).map(|i| i * 4).collect();
    let mut indices_4: Vec<u32> = (2097 * 4..total_num).map(|i| i * 4).collect();

    let expected_v3 = FileGroupChunks::new(maplit::btreemap! {
        FILE_GROUP_CHUNK_ID_OFFSET => indices_0.clone(),
        FILE_GROUP_CHUNK_ID_OFFSET + 1 => indices_1.clone(),
        FILE_GROUP_CHUNK_ID_OFFSET + 2 => indices_2.clone(),
        FILE_GROUP_CHUNK_ID_OFFSET + 3 => indices_3.clone(),
        FILE_GROUP_CHUNK_ID_OFFSET + 4 => indices_4.clone(),
    });
    assert_eq!(computed_file_group_chunks, expected_v3);

    let manifest = Manifest::new(StateSyncVersion::V4, file_table, chunk_table);
    let computed_file_group_chunks = build_file_group_chunks(&manifest);

    // Update the last file group chunk index to the medium file chunk index.
    indices_4.push(medium_chunk_index);
    let expected_v4 = FileGroupChunks::new(maplit::btreemap! {
        FILE_GROUP_CHUNK_ID_OFFSET => indices_0,
        FILE_GROUP_CHUNK_ID_OFFSET + 1 => indices_1,
        FILE_GROUP_CHUNK_ID_OFFSET + 2 => indices_2,
        FILE_GROUP_CHUNK_ID_OFFSET + 3 => indices_3,
        FILE_GROUP_CHUNK_ID_OFFSET + 4 => indices_4,
    });
    assert_eq!(computed_file_group_chunks, expected_v4);
}

#[test]
fn test_file_index_independent_file_hash() {
    let file1 = PathBuf::from("file1.bin");
    let file2 = PathBuf::from("file2.bin");
    let file3 = PathBuf::from("file3.bin");

    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    let dir = tempfile::TempDir::new().expect("failed to create a temporary directory");

    let root = dir.path();

    let find_file_hash = |manifest: &Manifest, file: &PathBuf| {
        manifest
            .file_table
            .iter()
            .find(|file_info| file_info.relative_path == *file)
            .unwrap_or_else(|| panic!("could not find {}", file.display()))
            .hash
    };

    let compute_file1_and_file3_hashes = |version: StateSyncVersion| {
        let mut thread_pool = scoped_threadpool::Pool::new(1);
        let manifest = compute_manifest(
            &mut thread_pool,
            &manifest_metrics,
            &no_op_logger(),
            version,
            &CheckpointLayout::new_untracked(root.to_path_buf(), Height::new(0)).unwrap(),
            1024,
            None,
            RehashManifest::No,
        )
        .expect("failed to compute manifest");

        (
            find_file_hash(&manifest, &file1),
            find_file_hash(&manifest, &file3),
        )
    };

    // A directory only containing `file1` and `file3`.
    fs::write(root.join(&file1), vec![1u8; 1000])
        .unwrap_or_else(|_| panic!("failed to create file '{}'", file1.display()));
    fs::write(root.join(&file3), vec![3u8; 1000])
        .unwrap_or_else(|_| panic!("failed to create file '{}'", file3.display()));

    let (file1_hash_v2_before, file3_hash_v2_before) =
        compute_file1_and_file3_hashes(StateSyncVersion::V2);
    let (file1_hash_before, file3_hash_before) =
        compute_file1_and_file3_hashes(CURRENT_STATE_SYNC_VERSION);

    // Directory now contains `file1`, `file2` and `file3`.
    fs::write(root.join(&file2), vec![2u8; 1000])
        .unwrap_or_else(|_| panic!("failed to create file '{}'", file2.display()));

    let (file1_hash_v2_after, file3_hash_v2_after) =
        compute_file1_and_file3_hashes(StateSyncVersion::V2);
    let (file1_hash_after, file3_hash_after) =
        compute_file1_and_file3_hashes(CURRENT_STATE_SYNC_VERSION);

    // The `file1` `V2` hashes should be equal (same contents, same file index).
    assert_eq!(file1_hash_v2_before, file1_hash_v2_after);
    // But the `file3` `V2` hashes should be different (different file index).
    assert_ne!(file3_hash_v2_before, file3_hash_v2_after);

    // And the `V3` hashes should be the same, regardless of file index.
    assert_eq!(file1_hash_before, file1_hash_after);
    assert_eq!(file3_hash_before, file3_hash_after);
}

#[test]
fn all_same_inodes_are_detected() {
    use std::fs::File;

    let base = tmpdir("base");
    let target = tmpdir("target");

    let create_file_in_target = |name| {
        let mut file = File::create(target.path().join(name)).unwrap();
        file.write_all(b"data").unwrap();
    };
    let create_different_file_in_base_and_target = |name| {
        let mut file = File::create(base.path().join(name)).unwrap();
        file.write_all(b"data").unwrap();
        let mut file = File::create(target.path().join(name)).unwrap();
        file.write_all(b"data").unwrap();
    };
    let create_same_file_in_base_and_target = |name| {
        let mut file = File::create(base.path().join(name)).unwrap();
        file.write_all(b"data").unwrap();
        fs::hard_link(base.path().join(name), target.path().join(name)).unwrap();
    };

    create_file_in_target("a_new");
    create_different_file_in_base_and_target("b_changed");
    create_same_file_in_base_and_target("c_same");
    create_different_file_in_base_and_target("d_changed");
    create_same_file_in_base_and_target("e_same");

    let base_manifest_info = BaseManifestInfo {
        base_manifest: Manifest::new(StateSyncVersion::V0, vec![], vec![]),
        base_height: Height::new(0),
        target_height: Height::new(1),
        base_checkpoint: CheckpointLayout::new_untracked(base.path().to_path_buf(), Height::new(0))
            .unwrap(),
    };

    let files = files_with_sizes(
        target.path(),
        "".into(),
        &mut scoped_threadpool::Pool::new(NUM_THREADS),
    )
    .unwrap();

    let result = files_with_same_inodes(
        &no_op_logger(),
        &base_manifest_info,
        &CheckpointLayout::new_untracked(target.path().to_path_buf(), Height::new(1)).unwrap(),
        &files,
        1024 * 1024,
        &mut scoped_threadpool::Pool::new(NUM_THREADS),
    );

    let expected = btreeset! {
        PathBuf::from("c_same"),
        PathBuf::from("e_same"),
    };

    assert_eq!(result, expected);
}
