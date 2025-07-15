use ic_cdk::api::stable::{StableReader, StableWriter};
use std::io::{Read, Write};

/// Writes `content` to stable memory.
/// Format:
///  [0..4] = length (4 bytes, little-endian)
///  [4.. ] = actual data
pub fn stable_set(content: &[u8]) -> std::io::Result<()> {
    let mut writer = StableWriter::default();

    // Write the length (4 bytes)
    let len_bytes = (content.len() as u32).to_le_bytes();
    writer.write_all(&len_bytes)?;

    // Write the data
    writer.write_all(content)?;

    // By default it flushes on drop, but let's be explicit
    writer.flush()
}

/// Reads back the data written by `stable_set`.
pub fn stable_get() -> std::io::Result<Vec<u8>> {
    let mut reader = StableReader::default();

    // Read the 4‑byte length
    let mut len_bytes = [0; 4];
    reader.read_exact(&mut len_bytes)?;
    let length = u32::from_le_bytes(len_bytes) as usize;

    // Read the data
    let mut data = vec![0; length];
    reader.read_exact(&mut data)?;
    Ok(data)
}
