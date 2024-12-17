pub mod pb;

/// Formats the 32 bytes of a hash as a hexadecimal string. Corresponds to 64 ascii symbols.
pub fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
