use ic_crypto_sha::Sha256;
use ic_state_manager::manifest::{
    hash::{file_hasher, manifest_hasher},
    STATE_SYNC_V1,
};
use ic_types::state_sync::{ChunkInfo, FileInfo};
use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    str::FromStr,
};

fn write_chunk_hash(chunk: &ChunkInfo, hasher: &mut Sha256) {
    hasher.write(&chunk.file_index.to_be_bytes());
    hasher.write(&chunk.size_bytes.to_be_bytes());
    hasher.write(&chunk.offset.to_be_bytes());
    hasher.write(&chunk.hash)
}

trait FileHasher {
    fn compute_file_hash(&self, chunk_entries: Vec<&ChunkInfo>) -> [u8; 32];
}

impl FileHasher for FileInfo {
    fn compute_file_hash(&self, chunk_entries: Vec<&ChunkInfo>) -> [u8; 32] {
        let mut hasher = file_hasher();
        hasher.write(&(chunk_entries.len() as u32).to_be_bytes());

        for entry in chunk_entries {
            write_chunk_hash(entry, &mut hasher);
        }
        hasher.finish()
    }
}

fn parse_hash(hash: &str) -> [u8; 32] {
    let hash = hex::decode(hash).unwrap();
    assert_eq!(hash.len(), 32);
    hash.try_into().unwrap()
}

fn compute_root_hash(
    file_table: BTreeMap<u32, FileInfo>,
    chunk_table: Vec<ChunkInfo>,
    state_sync_version: u32,
) -> [u8; 32] {
    let mut hasher = manifest_hasher();

    if state_sync_version >= STATE_SYNC_V1 {
        hasher.write(&state_sync_version.to_be_bytes());
    }

    hasher.write(&(file_table.len() as u32).to_be_bytes());

    for (idx, f) in file_table {
        let path = f.relative_path.to_str().unwrap();
        hasher.write(&(path.len() as u32).to_be_bytes());
        hasher.write(path.as_bytes());
        hasher.write(&f.size_bytes.to_be_bytes());
        let hash_recomputed = f.compute_file_hash(
            chunk_table
                .iter()
                .filter(|chunk| chunk.file_index == idx)
                .collect(),
        );
        assert_eq!(
            hash_recomputed, f.hash,
            "File hash mismatch in file with index {}",
            idx
        );
        hasher.write(&hash_recomputed);
    }

    if state_sync_version >= STATE_SYNC_V1 {
        hasher.write(&(chunk_table.len() as u32).to_be_bytes());

        for chunk in chunk_table {
            write_chunk_hash(&chunk, &mut hasher);
        }
    }

    hasher.finish()
}

/// A canister hash enables comparing canisters across states.
/// We compute the hash following the general rules for manifests:
///   * We use SHA-256 for collision resistance.
///   * We use a domain separator, "ic-canister-hash" in this case.
///   * We prefix variable-sized collection with the collection size.
/// See note [Manifest Hash] for more detail.
///
/// ```text
///   canister_hash := hash(dsep("ic-canister-hash")
///                         · file_count as u32
///                         · file*)
/// ```
///
/// The data written to the hash for each file is similar to whats written
/// for a `file_entry` in the conventional manifest, but the file hashes are
/// skipped. The rest of the content of the file hashes is directly inlined
/// (modulo whats described for chunks below).
///
/// ```text
///   file          := len(relative_path) as u32
///                    · relative_path
///                    · size_bytes as u64
///                    · chunk_count as u32
///                    · chunk*
/// ```
///
/// The data written to the hash for chunks is the same as for `chunk_entry`
/// in regular manifests except that the file index is skipped.
///
/// ```test
///   chunk         := size_bytes as u32
///                    · offset as u64
///                    · chunk_hash
/// ```
fn canister_hash(
    file_table: BTreeMap<u32, FileInfo>,
    chunk_table: Vec<ChunkInfo>,
    canister: &str,
) -> String {
    fn canister_hasher() -> Sha256 {
        let mut h = Sha256::new();
        let sep = "ic-canister-hash";
        h.write(&[sep.len() as u8][..]);
        h.write(sep.as_bytes());
        h
    }
    fn path(file_info: &FileInfo) -> &str {
        file_info.relative_path.to_str().unwrap()
    }

    let mut hasher = canister_hasher();

    let mut chunk_count = 0;

    let file_table = file_table
        .into_iter()
        .filter(|(_, f)| path(f).contains(&format!("canister_states/{}/", canister)))
        .collect::<BTreeMap<_, _>>();

    assert!(
        !file_table.is_empty(),
        "The provided canister ({}) does not match any files.",
        canister
    );

    hasher.write(&(file_table.len() as u32).to_be_bytes());
    for (idx, f) in file_table.iter() {
        const MIB: u64 = 1024 * 1024;
        let expected_chunks = (f.size_bytes + MIB - 1) / MIB;

        println!(
            "Processing file {}, size {}, expected chunks {}.",
            path(f),
            f.size_bytes,
            expected_chunks
        );

        hasher.write(&(path(f).len() as u32).to_be_bytes());
        hasher.write(path(f).as_bytes());
        hasher.write(&f.size_bytes.to_be_bytes());

        let chunks = chunk_table
            .iter()
            .filter(|chunk| chunk.file_index == *idx)
            .collect::<Vec<_>>();
        assert_eq!(
            expected_chunks,
            chunks.len() as u64,
            "Expected chunk count (assuming 1MiB chunks) {} does not match actual chunk count {}",
            expected_chunks,
            chunks.len()
        );
        chunk_count += chunks.len();

        hasher.write(&(chunks.len() as u32).to_be_bytes());

        for chunk in chunks {
            hasher.write(&chunk.size_bytes.to_be_bytes());
            hasher.write(&chunk.offset.to_be_bytes());
            hasher.write(&chunk.hash);
        }
    }

    let canister_hash = hex::encode(hasher.finish());
    println!(
        "Processed {} files and {} chunks. Canister hash: {}",
        file_table.len(),
        chunk_count,
        canister_hash,
    );

    canister_hash
}

fn extract_file_table(lines: &[String]) -> BTreeMap<u32, FileInfo> {
    lines
        .iter()
        // Abort as soon as the header of the chunk table is hit.
        .take_while(|line| !line.starts_with("CHUNK TABLE"))
        // Skip the 3 header lines of the file table.
        .skip(3)
        .map(|line| {
            let mut columns = line.split('|').into_iter().map(|column| column.trim());
            (
                columns.next().unwrap().parse().unwrap(),
                FileInfo {
                    size_bytes: columns.next().unwrap().parse().unwrap(),
                    hash: parse_hash(columns.next().unwrap()),
                    relative_path: PathBuf::from_str(columns.next().unwrap()).unwrap(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>()
}

fn extract_chunk_table(lines: &[String]) -> Vec<ChunkInfo> {
    lines
        .iter()
        // Skip until the beginning of the chunk table is reached.
        .skip_while(|line| !line.starts_with("CHUNK TABLE"))
        // Abort as soon as the root hash section is reached.
        .take_while(|line| !line.starts_with("ROOT HASH"))
        // Skip the 3 header lines of the chunk table.
        .skip(3)
        .map(|line| {
            let mut columns = line.split('|').into_iter().map(|column| column.trim());
            // Ignore chunk index; we don't need it
            columns.next();

            ChunkInfo {
                file_index: columns.next().unwrap().parse().unwrap(),
                offset: columns.next().unwrap().parse().unwrap(),
                size_bytes: columns.next().unwrap().parse().unwrap(),
                hash: parse_hash(columns.next().unwrap()),
            }
        })
        .collect::<Vec<_>>()
}

fn extract_root_hash(lines: &[String]) -> [u8; 32] {
    hex::decode(
        lines
            .iter()
            .find(|line| line.starts_with("ROOT HASH: "))
            .unwrap()
            .replace("ROOT HASH: ", ""),
    )
    .unwrap()
    .try_into()
    .unwrap()
}

fn parse_manifest(file: File) -> (BTreeMap<u32, FileInfo>, Vec<ChunkInfo>, [u8; 32]) {
    let manifest_lines: Vec<String> = BufReader::new(file)
        .lines()
        .into_iter()
        .map(|line| line.unwrap())
        .filter(|line| !line.is_empty())
        .collect();

    let file_table = extract_file_table(&manifest_lines);
    let chunk_table = extract_chunk_table(&manifest_lines);

    let root_hash = extract_root_hash(&manifest_lines);

    (file_table, chunk_table, root_hash)
}

fn verify_manifest(file: File, version: u32) -> Result<(), String> {
    if version > STATE_SYNC_V1 {
        panic!(
            "Unsupported state sync version provided {}. Max supported version {}",
            version, STATE_SYNC_V1
        );
    }

    let (file_table, chunk_table, root_hash) = parse_manifest(file);
    let root_hash_recomputed = compute_root_hash(file_table, chunk_table, version);
    assert_eq!(root_hash, root_hash_recomputed);
    println!(
        "Recomputed root hash: {}",
        hex::encode(root_hash_recomputed)
    );

    Ok(())
}

/// Parses a manifest in its textual representation as output by manifest
/// and computes a hash similar to the manifest root hash. The goal of
/// the canister hash is to provide a tool that allows to compare
/// canisters that are part of different states, i.e., so that a
/// canister hash of the same canister in two different states is the
/// same.
pub fn do_canister_hash(file: &Path, canister: &str) -> Result<(), String> {
    let (file_table, chunk_table, _) = parse_manifest(File::open(file).unwrap());
    canister_hash(file_table, chunk_table, canister);
    Ok(())
}

// Parses a manifest in its textual representation as output by manifest
// and recomputes the root hash using the information contained in it.
//
// Note that this means that it doesn't recompute the chunk hashes as
// recomputing these would require to have the respective files at hand.
pub fn do_verify_manifest(file: &Path, version: u32) -> Result<(), String> {
    verify_manifest(File::open(file).unwrap(), version)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{Seek, Write},
    };

    use ic_state_manager::manifest::{
        hash::{chunk_hasher, file_hasher},
        manifest_hash, CURRENT_STATE_SYNC_VERSION,
    };
    use ic_types::state_sync::{ChunkInfo, FileInfo, Manifest};

    use super::{canister_hash, verify_manifest};

    fn test_manifest_entry(
        file_index: u32,
        relative_path: &str,
        data: u8,
    ) -> (FileInfo, ChunkInfo) {
        let mut hasher = chunk_hasher();
        hasher.write(vec![data; 1024].as_slice());
        let chunk_0_hash = hasher.finish();

        hasher = file_hasher();
        hasher.write(&1_u32.to_be_bytes());
        hasher.write(&file_index.to_be_bytes());
        hasher.write(&1024_u32.to_be_bytes());
        hasher.write(&0_u64.to_be_bytes());
        hasher.write(&chunk_0_hash[..]);
        let file_0_hash = hasher.finish();

        (
            FileInfo {
                relative_path: relative_path.into(),
                size_bytes: 1024,
                hash: file_0_hash,
            },
            ChunkInfo {
                file_index,
                size_bytes: 1024,
                offset: 0,
                hash: chunk_0_hash,
            },
        )
    }

    fn test_manifest(file_infos: &[(FileInfo, ChunkInfo)]) -> (Manifest, String) {
        let manifest = Manifest::new(
            CURRENT_STATE_SYNC_VERSION,
            file_infos.iter().map(|info| info.0.clone()).collect(),
            file_infos.iter().map(|info| info.1.clone()).collect(),
        );

        (manifest.clone(), hex::encode(manifest_hash(&manifest)))
    }

    fn test_manifest_0() -> (Manifest, String) {
        test_manifest(&[
            test_manifest_entry(0, "root.bin", 0),
            test_manifest_entry(1, "canister_states/canister_0/test.bin", 1),
            test_manifest_entry(2, "canister_states/canister_1/test.bin", 2),
        ])
    }

    fn test_manifest_1() -> (Manifest, String) {
        test_manifest(&[test_manifest_entry(
            0,
            "canister_states/canister_0/test.bin",
            1,
        )])
    }

    #[test]
    fn recompute_root_hash_with_current_version_succeeds() {
        let (manifest, root_hash) = test_manifest_0();
        let mut tmp_file = tempfile::tempfile().unwrap();
        writeln!(&mut tmp_file, "{}", manifest).unwrap();
        writeln!(&mut tmp_file, "ROOT HASH: {}", root_hash).unwrap();
        tmp_file.seek(std::io::SeekFrom::Start(0)).unwrap();

        verify_manifest(tmp_file, CURRENT_STATE_SYNC_VERSION).unwrap();
    }

    #[test]
    fn canister_hashes_in_different_states_match() {
        fn compute_canister_hash(manifest: Manifest, canister: &str) -> String {
            canister_hash(
                manifest
                    .file_table
                    .iter()
                    .enumerate()
                    .map(|(i, f)| (i as u32, f.clone()))
                    .collect::<BTreeMap<_, _>>(),
                manifest.chunk_table.clone(),
                canister,
            )
        }

        let (manifest_0, root_hash_0) = test_manifest_0();
        let canister_hash_0 = compute_canister_hash(manifest_0, "canister_0");

        let (manifest_1, root_hash_1) = test_manifest_1();
        let canister_hash_1 = compute_canister_hash(manifest_1, "canister_0");

        assert_eq!(canister_hash_0, canister_hash_1);
        assert_ne!(root_hash_0, root_hash_1);
    }
}
