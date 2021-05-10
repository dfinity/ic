//! This module provides utilities to display byte slices using [run-length
//! encoding](https://en.wikipedia.org/wiki/Run-length_encoding) (RLE).
use std::fmt;

/// A wrapper of a byte slice that displays it as a string suitable for
/// debugging.
///
/// The display rules are:
///
/// * If the blob contains printable ASCII, it's printed as text.
///
/// * Otherwise, the bytes are displayed either as HEX or as RLE encoding
///   (depending on which one is shorter).
///
/// # Examples
///
/// ```
/// use ic_utils::rle::DebugBlob;
///
/// assert_eq!("Hello, World!", format!("{:?}", DebugBlob(b"Hello, World!")));
/// assert_eq!("0xdeadbeef", format!("{:?}", DebugBlob(&[0xde, 0xad, 0xbe, 0xef][..])));
/// assert_eq!("30×01", format!("{:?}", DebugBlob(&vec![1; 30][..])));
/// ```
#[derive(PartialEq)]
pub struct DebugBlob<'a>(pub &'a [u8]);

impl fmt::Debug for DebugBlob<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self
            .0
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        {
            return write!(
                f,
                "{}",
                std::str::from_utf8(self.0).expect("failed to convert ASCII bytes to str")
            );
        }
        let rle = display(self.0);
        if rle.len() < (self.0.len() + 1) * 2 {
            write!(f, "{}", rle)
        } else {
            write!(f, "0x{}", hex::encode(self.0))
        }
    }
}

/// Displays a byte slice using RLE.
///
/// This is mostly useful for displaying big blobs containing many zeroes.
///
/// # Examples
///
/// ```
/// use ic_utils::rle::display;
/// assert_eq!("", display(&[]));
/// assert_eq!("8×01", display(&[1, 1, 1, 1, 1, 1, 1, 1]));
/// assert_eq!("5×01 3×02", display(&[1, 1, 1, 1, 1, 2, 2, 2]));
/// assert_eq!(
///     "1×01 1×02 1×03 1×04 1×05 1×40",
///     display(&[1, 2, 3, 4, 5, 64])
/// );
/// ```
pub fn display(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "".to_owned();
    }

    let mut buf = String::new();
    let mut prefix = "";
    let mut emit = |count, byte| {
        fmt::write(&mut buf, format_args!("{}{}×{:02x}", prefix, count, byte))
            .expect("Failed to write to string");
        prefix = " ";
    };

    let mut last_byte = bytes[0];
    let mut count = 1;

    for byte in &bytes[1..] {
        if *byte == last_byte {
            count += 1
        } else {
            emit(count, last_byte);
            last_byte = *byte;
            count = 1
        }
    }
    emit(count, last_byte);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "left: `8×01 4×02 4×03`,\n right: `8×01 4×02 3×03 1×04`")]
    fn test_debug_blob() {
        assert_eq!(
            DebugBlob(&[1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3]),
            DebugBlob(&[1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4])
        );
    }
}
