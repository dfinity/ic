use ic_crypto_sha2::Sha256;
use ic_state_manager::manifest::validate_manifest;
use ic_types::crypto::CryptoHash;
use ic_types::state_sync::{
    ChunkInfo, FileInfo, Manifest, StateSyncVersion, MAX_SUPPORTED_STATE_SYNC_VERSION,
};
use ic_types::CryptoHashOfState;
use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    str::FromStr,
};

fn parse_hash(hash: &str) -> [u8; 32] {
    let hash = hex::decode(hash).unwrap();
    assert_eq!(hash.len(), 32);
    hash.try_into().unwrap()
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
fn canister_hash(file_table: Vec<FileInfo>, chunk_table: Vec<ChunkInfo>, canister: &str) -> String {
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
        .enumerate()
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
            .filter(|chunk| chunk.file_index == *idx as u32)
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

fn extract_manifest_version(lines: &[String]) -> StateSyncVersion {
    let version = lines
        .iter()
        .find(|line| line.starts_with("MANIFEST VERSION: V"))
        .unwrap()
        .replace("MANIFEST VERSION: V", "")
        .parse::<u32>()
        .unwrap();
    StateSyncVersion::try_from(version).unwrap()
}

fn extract_file_table(lines: &[String]) -> Vec<FileInfo> {
    lines
        .iter()
        // Skip until the beginning of the file table is reached.
        .skip_while(|line| !line.starts_with("FILE TABLE"))
        // Abort as soon as the header of the chunk table is hit.
        .take_while(|line| !line.starts_with("CHUNK TABLE"))
        // Skip the 3 header lines of the file table.
        .skip(3)
        .enumerate()
        .map(|(i, line)| {
            let mut columns = line.split('|').map(|column| column.trim());
            assert_eq!(
                i,
                columns.next().unwrap().parse::<usize>().unwrap(),
                "Missing file index {}",
                i
            );
            FileInfo {
                size_bytes: columns.next().unwrap().parse().unwrap(),
                hash: parse_hash(columns.next().unwrap()),
                relative_path: PathBuf::from_str(columns.next().unwrap()).unwrap(),
            }
        })
        .collect()
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
            let mut columns = line.split('|').map(|column| column.trim());
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

pub(crate) fn parse_manifest(
    file: File,
) -> (StateSyncVersion, Vec<FileInfo>, Vec<ChunkInfo>, [u8; 32]) {
    let manifest_lines: Vec<String> = BufReader::new(file)
        .lines()
        .map(|line| line.unwrap())
        .filter(|line| !line.is_empty())
        .collect();

    let manifest_version = extract_manifest_version(&manifest_lines);
    let file_table = extract_file_table(&manifest_lines);
    let chunk_table = extract_chunk_table(&manifest_lines);

    let root_hash = extract_root_hash(&manifest_lines);

    (manifest_version, file_table, chunk_table, root_hash)
}

fn verify_manifest(file: File) -> Result<(), String> {
    let (version, file_table, chunk_table, root_hash) = parse_manifest(file);
    if version > MAX_SUPPORTED_STATE_SYNC_VERSION {
        panic!(
            "Unsupported state sync version provided {:?}. Max supported version {:?}",
            version, MAX_SUPPORTED_STATE_SYNC_VERSION
        );
    }

    let manifest = Manifest::new(version, file_table, chunk_table);
    validate_manifest(
        &manifest,
        &CryptoHashOfState::from(CryptoHash(root_hash.to_vec())),
    )
    .unwrap();
    println!("Root hash: {}", hex::encode(root_hash));

    Ok(())
}

/// Parses a manifest in its textual representation as output by manifest
/// and computes a hash similar to the manifest root hash. The goal of
/// the canister hash is to provide a tool that allows to compare
/// canisters that are part of different states, i.e., so that a
/// canister hash of the same canister in two different states is the
/// same.
pub fn do_canister_hash(file: &Path, canister: &str) -> Result<(), String> {
    let (_, file_table, chunk_table, _) = parse_manifest(File::open(file).unwrap());
    canister_hash(file_table, chunk_table, canister);
    Ok(())
}

// Parses a manifest in its textual representation as output by manifest
// and recomputes the root hash using the information contained in it.
//
// Note that this means that it doesn't recompute the chunk hashes as
// recomputing these would require to have the respective files at hand.
pub fn do_verify_manifest(file: &Path) -> Result<(), String> {
    verify_manifest(File::open(file).unwrap())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use ic_state_manager::manifest::{
        hash::{chunk_hasher, file_hasher},
        manifest_hash,
    };
    use ic_types::state_sync::{
        ChunkInfo, FileInfo, Manifest, StateSyncVersion, CURRENT_STATE_SYNC_VERSION,
    };

    use super::{canister_hash, verify_manifest};

    fn test_manifest_entry(
        version: StateSyncVersion,
        file_index: u32,
        relative_path: &str,
        data: u8,
    ) -> (FileInfo, ChunkInfo) {
        let mut hasher = chunk_hasher();
        hasher.write(vec![data; 1024].as_slice());
        let chunk_0_hash = hasher.finish();

        hasher = file_hasher();
        hasher.write(&1_u32.to_be_bytes());
        if version < StateSyncVersion::V3 {
            hasher.write(&file_index.to_be_bytes());
        }
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

    fn test_manifest(
        version: StateSyncVersion,
        file_infos: &[(FileInfo, ChunkInfo)],
    ) -> (Manifest, String) {
        let manifest = Manifest::new(
            version,
            file_infos.iter().map(|info| info.0.clone()).collect(),
            file_infos.iter().map(|info| info.1.clone()).collect(),
        );

        (manifest.clone(), hex::encode(manifest_hash(&manifest)))
    }

    fn test_manifest_current_version() -> (Manifest, String) {
        let version = CURRENT_STATE_SYNC_VERSION;
        test_manifest(
            version,
            &[
                test_manifest_entry(version, 0, "canister_states/canister_0/test.bin", 0),
                test_manifest_entry(version, 1, "root.bin", 1),
            ],
        )
    }

    fn test_manifest_2_current_version() -> (Manifest, String) {
        let version = CURRENT_STATE_SYNC_VERSION;
        test_manifest(
            version,
            &[test_manifest_entry(
                version,
                0,
                "canister_states/canister_0/test.bin",
                0,
            )],
        )
    }

    fn test_manifest_v2() -> (Manifest, String) {
        let version = StateSyncVersion::V2;
        test_manifest(
            version,
            &[
                test_manifest_entry(version, 0, "canister_states/canister_0/test.bin", 0),
                test_manifest_entry(version, 1, "canister_states/canister_1/test.bin", 1),
                test_manifest_entry(version, 2, "root.bin", 2),
            ],
        )
    }

    #[test]
    fn recompute_root_hash_with_current_version_succeeds() {
        let (manifest, root_hash) = test_manifest_current_version();
        let mut tmp_file = tempfile::tempfile().unwrap();
        writeln!(&mut tmp_file, "{}", manifest).unwrap();
        writeln!(&mut tmp_file, "ROOT HASH: {}", root_hash).unwrap();
        tmp_file.seek(std::io::SeekFrom::Start(0)).unwrap();

        verify_manifest(tmp_file).unwrap();
    }

    #[test]
    fn recompute_root_hash_v2_succeeds() {
        let (manifest, root_hash) = test_manifest_v2();
        let mut tmp_file = tempfile::tempfile().unwrap();
        writeln!(&mut tmp_file, "{}", manifest).unwrap();
        writeln!(&mut tmp_file, "ROOT HASH: {}", root_hash).unwrap();
        tmp_file.seek(std::io::SeekFrom::Start(0)).unwrap();

        verify_manifest(tmp_file).unwrap();
    }

    #[test]
    fn canister_hashes_in_different_states_match() {
        fn compute_canister_hash(manifest: Manifest, canister: &str) -> String {
            canister_hash(
                manifest.file_table.clone(),
                manifest.chunk_table.clone(),
                canister,
            )
        }

        let (manifest_0, root_hash_0) = test_manifest_current_version();
        let canister_hash_0 = compute_canister_hash(manifest_0, "canister_0");

        let (manifest_1, root_hash_1) = test_manifest_2_current_version();
        let canister_hash_1 = compute_canister_hash(manifest_1, "canister_0");

        assert_eq!(canister_hash_0, canister_hash_1);
        assert_ne!(root_hash_0, root_hash_1);
    }
}
