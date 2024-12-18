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

/// Trait for strings that can be represented in an ellipsis format.
pub trait StrEllipsize {
    /// Ellipsize the string with a max length and prefix percentage `[0, 100]`.
    ///
    /// Returns the original string if it's shorter or equal than the max length.
    fn ellipsize(&self, max_len: usize, prefix_percentage: usize) -> String;
}

impl StrEllipsize for str {
    fn ellipsize(&self, max_len: usize, prefix_percentage: usize) -> String {
        if self.len() <= max_len {
            return self.to_string();
        }

        const ELLIPSIS: &str = "...";
        assert!(max_len >= ELLIPSIS.len());

        // Deduct the ellipsis length to get the available space for prefix and suffix combined.
        let budget = max_len.saturating_sub(ELLIPSIS.len());

        // Calculate the length of the prefix based on the given percentage.
        let prefix_len = (max_len * prefix_percentage.clamp(0, 100) / 100).min(budget);
        let suffix_len = budget - prefix_len;

        // Construct the ellipsized string.
        let mut ellipsized = String::with_capacity(max_len);
        ellipsized.push_str(self.safe_truncate(prefix_len));
        ellipsized.push_str(ELLIPSIS);
        ellipsized.push_str(self.safe_truncate_right(suffix_len));
        ellipsized
    }
}

#[test]
fn test_ellipsize() {
    assert_eq!("123454321".ellipsize(3, 0), "...");
    assert_eq!("123454321".ellipsize(3, 50), "...");
    assert_eq!("123454321".ellipsize(3, 100), "...");

    assert_eq!("123454321".ellipsize(4, 0), "...1");
    assert_eq!("123454321".ellipsize(4, 20), "...1");
    assert_eq!("123454321".ellipsize(4, 25), "1...");
    assert_eq!("123454321".ellipsize(4, 100), "1...");
    assert_eq!("123454321".ellipsize(4, 200), "1...");

    assert_eq!("123454321".ellipsize(5, 0), "...21");
    assert_eq!("123454321".ellipsize(5, 20), "1...1");
    assert_eq!("123454321".ellipsize(5, 40), "12...");
    assert_eq!("123454321".ellipsize(5, 100), "12...");
    assert_eq!("123454321".ellipsize(5, 200), "12...");

    assert_eq!("123454321".ellipsize(8, 0), "...54321");
    assert_eq!("123454321".ellipsize(8, 13), "1...4321");
    assert_eq!("123454321".ellipsize(8, 25), "12...321");
    assert_eq!("123454321".ellipsize(8, 38), "123...21");
    assert_eq!("123454321".ellipsize(8, 50), "1234...1");
    assert_eq!("123454321".ellipsize(8, 75), "12345...");
    assert_eq!("123454321".ellipsize(8, 100), "12345...");
    assert_eq!("123454321".ellipsize(8, 200), "12345...");

    assert_eq!("123454321".ellipsize(9, 50), "123454321");

    // A string consisting characters with 3-byte UTF-8 encodings.
    assert_eq!("₿₿₿€€€".ellipsize(3, 2), "...");
    assert_eq!("₿₿₿€€€".ellipsize(9, 40), "₿...€");
}
