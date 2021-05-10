/// Formats the first `max_bytes_to_format` bytes of a byte slice as
/// hexadecimal.
pub fn truncate_and_format(slice: &[u8], max_bytes_to_format: usize) -> String {
    let truncated = &slice[..slice.len().min(max_bytes_to_format)];
    let content_hex = hex::encode(&truncated);
    let ellipsis = if truncated.len() < slice.len() {
        "…"
    } else {
        ""
    };
    let size_descriptor = match slice.len() {
        0 => "empty".to_string(),
        1..=3 => String::default(), // For small amount of bytes, it's easy to count
        n => format!("{} bytes;", n),
    };
    format!("{}{}{}", size_descriptor, content_hex, ellipsis)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(vec: Vec<u8>, max_bytes_to_format: usize) -> String {
        truncate_and_format(vec.as_slice(), max_bytes_to_format)
    }

    #[test]
    fn test_truncate_and_format() {
        assert_eq!(f(vec![], 5), "empty");
        assert_eq!(f(vec![0], 5), "00");
        assert_eq!(f(vec![255, 0], 5), "ff00");
        assert_eq!(f(vec![1, 2, 3], 5), "010203");
        assert_eq!(f(vec![0, 1, 15, 255], 5), "4 bytes;00010fff");
        assert_eq!(
            f((0 as u8..100 as u8).collect(), 5),
            "100 bytes;0001020304…"
        );
        assert_eq!(
            f((0 as u8..100 as u8).collect(), 6),
            "100 bytes;000102030405…"
        );
    }
}
