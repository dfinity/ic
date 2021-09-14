use super::{
    compute_manifest, diff_manifest, filter_out_zero_chunks, hash::ManifestHash, manifest_hash,
    validate_chunk, validate_manifest, ChunkValidationError, DiffScript, ManifestValidationError,
    STATE_SYNC_V1,
};

use ic_crypto_sha::Sha256;
use ic_types::{
    crypto::CryptoHash,
    state_sync::{decode_manifest, encode_manifest, ChunkInfo, FileInfo, Manifest},
    CryptoHashOfState,
};

use std::collections::{HashMap, HashSet};
use std::fs;

macro_rules! hash_concat {
    ($( $x:expr ),*) => {
        {
            let mut h = Sha256::new();
            $( $x.update_hash(&mut h); )*
            h.finish()
        }
    }
}

fn simple_manifest() -> ([u8; 32], Manifest) {
    let chunk_0_hash = hash_concat!(14u8, b"ic-state-chunk", vec![0u8; 1000].as_slice());
    let chunk_1_hash = hash_concat!(14u8, b"ic-state-chunk", vec![1u8; 1024].as_slice());
    let chunk_2_hash = hash_concat!(14u8, b"ic-state-chunk", vec![1u8; 1024].as_slice());
    let chunk_3_hash = hash_concat!(14u8, b"ic-state-chunk", vec![2u8; 1024].as_slice());
    let chunk_4_hash = hash_concat!(14u8, b"ic-state-chunk", vec![2u8; 26].as_slice());

    let file_0_hash = hash_concat!(
        13u8,
        b"ic-state-file",
        1u32,
        0u32,
        1000u32,
        0u64,
        &chunk_0_hash[..]
    );
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
    let file_2_hash = hash_concat!(
        13u8,
        b"ic-state-file",
        2u32,
        2u32,
        1024u32,
        0u64,
        &chunk_3_hash[..],
        2u32,
        26u32,
        1024u64,
        &chunk_4_hash[..]
    );
    let file_3_hash = hash_concat!(13u8, b"ic-state-file", 0u32);

    let manifest = Manifest {
        version: STATE_SYNC_V1,
        file_table: vec![
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
        ],
        chunk_table: vec![
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
        ],
    };

    let expected_hash = hash_concat!(
        17u8,
        b"ic-state-manifest",
        STATE_SYNC_V1,
        // files
        4u32,
        "root.bin",
        1000u64,
        &file_0_hash[..],
        "subdir/memory",
        2048u64,
        &file_1_hash[..],
        "subdir/metadata",
        1050u64,
        &file_2_hash[..],
        "subdir/queue",
        0u64,
        &file_3_hash[..],
        // chunks
        5u32,
        // chunk 0
        0u32,
        1000u32,
        0u64,
        &chunk_0_hash[..],
        // chunk 1
        1u32,
        1024u32,
        0u64,
        &chunk_1_hash[..],
        // chunk 2
        1u32,
        1024u32,
        1024u64,
        &chunk_2_hash[..],
        // chunk 3
        2u32,
        1024u32,
        0u64,
        &chunk_3_hash[..],
        // chunk 4
        2u32,
        26u32,
        1024u64,
        &chunk_4_hash[..]
    );

    (expected_hash, manifest)
}

#[test]
fn test_simple_manifest_computation() {
    let dir = tempfile::TempDir::new().expect("failed to create a temporary directory");

    let root = dir.path();
    fs::write(root.join("root.bin"), vec![0u8; 1000]).expect("failed to create file 'test.bin'");

    let subdir = root.join("subdir");
    fs::create_dir_all(&subdir).expect("failed to create dir 'subdir'");
    fs::write(subdir.join("memory"), vec![1u8; 2048]).expect("failed to create file 'memory'");
    fs::write(subdir.join("queue"), vec![0u8; 0]).expect("failed to create file 'queue'");
    fs::write(subdir.join("metadata"), vec![2u8; 1050]).expect("failed to create file 'queue'");

    let manifest =
        compute_manifest(STATE_SYNC_V1, &root, 1024).expect("failed to compute manifest");

    let (expected_hash, expected_manifest) = simple_manifest();

    assert_eq!(manifest, expected_manifest);
    assert_eq!(expected_hash, manifest_hash(&manifest));
}

#[test]
fn simple_manifest_passes_validation() {
    let (expected_hash, manifest) = simple_manifest();
    assert_eq!(
        Ok(()),
        validate_manifest(
            &manifest,
            &CryptoHashOfState::from(CryptoHash(expected_hash.to_vec()))
        )
    );
}

#[test]
fn bad_root_hash_detected() {
    let (manifest_hash, manifest) = simple_manifest();
    let bogus_hash = CryptoHashOfState::from(CryptoHash(vec![1u8; 32]));
    assert_eq!(
        validate_manifest(&manifest, &bogus_hash),
        Err(ManifestValidationError::InvalidRootHash {
            expected_hash: bogus_hash.get_ref().0.clone(),
            actual_hash: manifest_hash.to_vec(),
        })
    );
}

#[test]
fn bad_file_hash_detected() {
    let (manifest_hash, mut manifest) = simple_manifest();
    let actual_hash = manifest.file_table[0].hash.to_vec();
    manifest.file_table[0].hash = [1u8; 32];
    let root_hash = CryptoHashOfState::from(CryptoHash(manifest_hash.to_vec()));
    assert_eq!(
        validate_manifest(&manifest, &root_hash),
        Err(ManifestValidationError::InvalidFileHash {
            relative_path: manifest.file_table[0].relative_path.clone(),
            expected_hash: vec![1u8; 32],
            actual_hash,
        })
    );
}

#[test]
fn bad_chunk_size_detected() {
    let (_, manifest) = simple_manifest();
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

#[test]
fn bad_chunk_hash_detected() {
    let (_, manifest) = simple_manifest();
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

#[test]
fn orphan_chunk_detected() {
    let (manifest_hash, mut manifest) = simple_manifest();
    manifest.chunk_table.push(ChunkInfo {
        file_index: 100,
        size_bytes: 100,
        offset: 0,
        hash: [0; 32],
    });
    let root_hash = CryptoHashOfState::from(CryptoHash(manifest_hash.to_vec()));
    match validate_manifest(&manifest, &root_hash) {
        Err(ManifestValidationError::InvalidRootHash { .. }) => (),
        other => panic!(
            "Expected an orphan chunk to change the root hash, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_diff_simple_manifest() {
    let (_, manifest_old) = simple_manifest();
    let mut manifest_new = manifest_old.clone();
    let len = manifest_new.file_table.len();
    let indices = (0..len).collect::<Vec<usize>>();
    let copy_files: HashMap<_, _> = indices
        .clone()
        .into_iter()
        .zip(indices.into_iter())
        .collect();
    assert_eq!(
        diff_manifest(&manifest_old, &manifest_new),
        DiffScript {
            copy_files,
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

    manifest_new.file_table[1] = FileInfo {
        relative_path: "subdir/memory".into(),
        size_bytes: 2048,
        hash: file_1_hash,
    };

    manifest_new.chunk_table[2] = ChunkInfo {
        file_index: 1,
        size_bytes: 1024,
        offset: 1024,
        hash: chunk_2_hash,
    };

    let copy_files: HashMap<usize, usize> = maplit::hashmap! {
        0 => 0,
        2 => 2,
        3 => 3,
    };

    let copy_chunks: HashMap<usize, usize> = maplit::hashmap! {
        1 => 2,
    };

    let fetch_chunks: HashSet<usize> = maplit::hashset! {2};

    assert_eq!(
        diff_manifest(&manifest_old, &manifest_new),
        DiffScript {
            copy_files,
            copy_chunks,
            fetch_chunks,
            zeros_chunks: 0,
        }
    );
}

#[test]
fn test_diff_manifest() {
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

    let manifest_old =
        compute_manifest(STATE_SYNC_V1, &root, 1024 * 1024).expect("failed to compute manifest");

    fs::write(subdir.join("metadata"), vec![3u8; 2048 * 1024])
        .expect("failed to write file 'metadata'");
    fs::write(subdir.join("queue"), vec![0u8; 2048 * 1024]).expect("failed to write file 'queue'");
    // The files in the manifest is sorted by relative path. The index of file
    // 'metadata' is 2. The indices of its chunks are 3 and 4.
    let manifest_new =
        compute_manifest(STATE_SYNC_V1, &root, 1024 * 1024).expect("failed to compute manifest");

    let copy_files: HashMap<usize, usize> = maplit::hashmap! {
        0 => 0,
        1 => 1,
    };

    // chunk_4 does change but it is the same as the original chunk_3.
    let copy_chunks: HashMap<usize, usize> = maplit::hashmap! {
        3 => 3,
        4 => 3,
    };

    assert_eq!(
        diff_manifest(&manifest_old, &manifest_new),
        DiffScript {
            copy_files,
            copy_chunks,
            fetch_chunks: Default::default(),
            zeros_chunks: 2,
        }
    );
}

#[test]
fn test_filter_all_zero_chunks() {
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

    let manifest =
        compute_manifest(STATE_SYNC_V1, &root, 1024 * 1024).expect("failed to compute manifest");

    let fetch_chunks: HashSet<usize> = maplit::hashset! {0, 3, 4, 6};

    assert_eq!(filter_out_zero_chunks(&manifest), fetch_chunks);
}

#[test]
fn test_simple_manifest_encoding_roundtrip() {
    let (_hash, manifest) = simple_manifest();
    assert_eq!(
        decode_manifest(&encode_manifest(&manifest)[..]),
        Ok(manifest)
    );
}
