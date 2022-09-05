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
    path::PathBuf,
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

fn verify_manifest(file: File, version: u32) -> Result<(), String> {
    if version > STATE_SYNC_V1 {
        panic!(
            "Unsupported state sync version provided {}. Max supported version {}",
            version, STATE_SYNC_V1
        );
    }

    let manifest_lines: Vec<String> = BufReader::new(file)
        .lines()
        .into_iter()
        .map(|line| line.unwrap())
        .filter(|line| !line.is_empty())
        .collect();

    let file_table = extract_file_table(&manifest_lines);
    let chunk_table = extract_chunk_table(&manifest_lines);

    let root_hash = extract_root_hash(&manifest_lines);
    let root_hash_recomputed = compute_root_hash(file_table, chunk_table, version);
    assert_eq!(root_hash, root_hash_recomputed);
    println!(
        "Recomputed root hash: {}",
        hex::encode(root_hash_recomputed)
    );

    Ok(())
}

// Parses a manifest in its textual representation as output by manifest
// and recomputes the root hash using the information contained in it.
//
// Note that this means that it doesn't recompute the chunk hashes as
// recomputing these would require to have the respective files at hand.
pub fn do_verify_manifest(file: PathBuf, version: u32) -> Result<(), String> {
    verify_manifest(File::open(file).unwrap(), version)
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use ic_state_manager::manifest::{
        hash::{chunk_hasher, file_hasher},
        manifest_hash, CURRENT_STATE_SYNC_VERSION,
    };
    use ic_types::state_sync::{ChunkInfo, FileInfo, Manifest};

    use super::verify_manifest;

    fn test_manifest() -> (Manifest, String) {
        let mut hasher = chunk_hasher();
        hasher.write(vec![1u8; 1024].as_slice());
        let chunk_0_hash = hasher.finish();

        hasher = file_hasher();
        hasher.write(&1_u32.to_be_bytes());
        hasher.write(&0_u32.to_be_bytes());
        hasher.write(&1024_u32.to_be_bytes());
        hasher.write(&0_u64.to_be_bytes());
        hasher.write(&chunk_0_hash[..]);
        let file_0_hash = hasher.finish();

        let manifest = Manifest::new(
            CURRENT_STATE_SYNC_VERSION,
            vec![FileInfo {
                relative_path: "root.bin".into(),
                size_bytes: 1024,
                hash: file_0_hash,
            }],
            vec![ChunkInfo {
                file_index: 0,
                size_bytes: 1024,
                offset: 0,
                hash: chunk_0_hash,
            }],
        );

        (manifest.clone(), hex::encode(manifest_hash(&manifest)))
    }

    #[test]
    fn recompute_root_hash_with_current_version_succeeds() {
        let (manifest, root_hash) = test_manifest();
        let mut tmp_file = tempfile::tempfile().unwrap();
        writeln!(&mut tmp_file, "{}", manifest).unwrap();
        writeln!(&mut tmp_file, "ROOT HASH: {}", root_hash).unwrap();
        tmp_file.seek(std::io::SeekFrom::Start(0)).unwrap();

        verify_manifest(tmp_file, CURRENT_STATE_SYNC_VERSION).unwrap();
    }
}
