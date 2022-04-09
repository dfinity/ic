//! Helpers for truncating string slices at character boundaries.

/// Trait, implemented for `str`, for truncating string slices at character
/// boundaries.
pub trait StrTruncate {
    /// Returns a prefix of at most `max_len` bytes, cut at a character boundary.
    ///
    /// Calling this with a `max_len` greater than the slice length will return
    /// the whole slice.
    fn safe_truncate(&self, max_len: usize) -> &str;

    /// Returns a suffix of at most `max_len` bytes, cut at a character boundary.
    ///
    /// Calling this with a `max_len` greater than the slice length will return
    /// the whole slice.
    fn safe_truncate_right(&self, max_len: usize) -> &str;
}

impl StrTruncate for str {
    fn safe_truncate(&self, max_len: usize) -> &str {
        if self.len() > max_len {
            let mut len = max_len;
            while len > 0 && !self.is_char_boundary(len) {
                len -= 1;
            }
            &self[..len]
        } else {
            self
        }
    }

    fn safe_truncate_right(&self, max_len: usize) -> &str {
        if self.len() > max_len {
            let mut left = self.len() - max_len;
            while left < self.len() && !self.is_char_boundary(left) {
                left += 1;
            }
            &self[left..]
        } else {
            self
        }
    }
}

#[test]
fn test_safe_truncate() {
    assert_eq!("abc", "abcde".safe_truncate(3));

    // A unicode string consisting of 2 3-byte characters.
    let s = "₿€";
    assert_eq!(6, s.len());

    assert_eq!("", s.safe_truncate(0));
    assert_eq!("", s.safe_truncate(1));
    assert_eq!("", s.safe_truncate(2));
    assert_eq!("₿", s.safe_truncate(3));
    assert_eq!("₿", s.safe_truncate(4));
    assert_eq!("₿", s.safe_truncate(5));
    assert_eq!("₿€", s.safe_truncate(6));
    assert_eq!("₿€", s.safe_truncate(7));
}

#[test]
fn test_safe_truncate_right() {
    assert_eq!("cde", "abcde".safe_truncate_right(3));

    // A unicode string consisting of 2 3-byte characters.
    let s = "₿€";
    assert_eq!(6, s.len());

    assert_eq!("", s.safe_truncate_right(0));
    assert_eq!("", s.safe_truncate_right(1));
    assert_eq!("", s.safe_truncate_right(2));
    assert_eq!("€", s.safe_truncate_right(3));
    assert_eq!("€", s.safe_truncate_right(4));
    assert_eq!("€", s.safe_truncate_right(5));
    assert_eq!("₿€", s.safe_truncate_right(6));
    assert_eq!("₿€", s.safe_truncate_right(7));
}
