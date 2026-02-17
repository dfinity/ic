use ic_state_manager::manifest::validate_manifest;
use ic_state_manager::state_sync::types::{
    ChunkInfo, FileInfo, MAX_SUPPORTED_STATE_SYNC_VERSION, Manifest,
};
use ic_types::CryptoHashOfState;
use ic_types::crypto::CryptoHash;
use ic_types::state_sync::StateSyncVersion;
use std::{
    convert::TryInto,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    str::FromStr,
};

type StateHash = [u8; 32];

fn parse_hash(hash: &str) -> StateHash {
    let hash = hex::decode(hash).unwrap();
    assert_eq!(hash.len(), 32);
    hash.try_into().unwrap()
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
                "Missing file index {i}"
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

fn extract_root_hash(lines: &[String]) -> Result<StateHash, String> {
    hex::decode(
        lines
            .iter()
            .find(|line| line.starts_with("ROOT HASH: "))
            .ok_or_else(|| String::from("Failed to find the root hash in the manifest"))?
            .replace("ROOT HASH: ", ""),
    )
    .map_err(|err| format!("Failed to decode the root hash: {err}"))?
    .try_into()
    .map_err(|err| format!("Failed to decode the root hash: {err:?}"))
}

pub fn parse_manifest(
    file: File,
) -> Result<(StateSyncVersion, Vec<FileInfo>, Vec<ChunkInfo>, StateHash), String> {
    let manifest_lines: Vec<String> = BufReader::new(file)
        .lines()
        .map(|line| line.unwrap())
        .filter(|line| !line.is_empty())
        .collect();

    let manifest_version = extract_manifest_version(&manifest_lines);
    let file_table = extract_file_table(&manifest_lines);
    let chunk_table = extract_chunk_table(&manifest_lines);

    let root_hash = extract_root_hash(&manifest_lines)?;

    Ok((manifest_version, file_table, chunk_table, root_hash))
}

pub fn verify_manifest(file: File) -> Result<StateHash, String> {
    let (version, file_table, chunk_table, root_hash) = parse_manifest(file)?;
    if version > MAX_SUPPORTED_STATE_SYNC_VERSION {
        panic!(
            "Unsupported state sync version provided {version:?}. Max supported version {MAX_SUPPORTED_STATE_SYNC_VERSION:?}"
        );
    }

    let manifest = Manifest::new(version, file_table, chunk_table);
    validate_manifest(
        &manifest,
        &CryptoHashOfState::from(CryptoHash(root_hash.to_vec())),
    )
    .map_err(|err| format!("Failed to validate the manifest: {err}"))?;

    Ok(root_hash)
}

// Parses a manifest in its textual representation as output by manifest
// and recomputes the root hash using the information contained in it.
//
// Note that this means that it doesn't recompute the chunk hashes as
// recomputing these would require to have the respective files at hand.
pub fn do_verify_manifest(file: &Path) -> Result<(), String> {
    let root_hash = verify_manifest(File::open(file).unwrap())?;

    println!("Root hash: {}", hex::encode(root_hash));

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use ic_state_manager::manifest::{
        hash::{chunk_hasher, file_hasher},
        manifest_hash,
    };
    use ic_state_manager::state_sync::types::{ChunkInfo, FileInfo, Manifest};
    use ic_types::state_sync::{CURRENT_STATE_SYNC_VERSION, StateSyncVersion};

    use super::verify_manifest;

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
        writeln!(&mut tmp_file, "{manifest}").unwrap();
        writeln!(&mut tmp_file, "ROOT HASH: {root_hash}").unwrap();
        tmp_file.seek(std::io::SeekFrom::Start(0)).unwrap();

        verify_manifest(tmp_file).unwrap();
    }

    #[test]
    fn recompute_root_hash_v2_succeeds() {
        let (manifest, root_hash) = test_manifest_v2();
        let mut tmp_file = tempfile::tempfile().unwrap();
        writeln!(&mut tmp_file, "{manifest}").unwrap();
        writeln!(&mut tmp_file, "ROOT HASH: {root_hash}").unwrap();
        tmp_file.seek(std::io::SeekFrom::Start(0)).unwrap();

        verify_manifest(tmp_file).unwrap();
    }
}
