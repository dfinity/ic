//! Formatting integers with a `_` separator between groups of three digits.

use std::fmt::Display;

/// Formats `value` by inserting an underscore between every group of three
/// digits, counting from the right.
///
/// Only the first run of ASCII decimal digits in the value's [`Display`]
/// representation is grouped, so a leading sign or a trailing fraction is left
/// untouched (e.g. `-12345.6` becomes `-12_345.6`). This reproduces the
/// behaviour of the [`thousands`](https://crates.io/crates/thousands) crate's
/// `Separable::separate_with_underscores`, which it replaces.
///
/// # Example
/// ```
/// use ic_utils_thousands::separate_with_underscores;
///
/// assert_eq!(separate_with_underscores(1234567_u64), "1_234_567");
/// assert_eq!(separate_with_underscores(12345_u32), "12_345");
/// assert_eq!(separate_with_underscores(42_u8), "42");
/// ```
pub fn separate_with_underscores<T: Display>(value: T) -> String {
    let s = value.to_string();
    // Locate the first run of ASCII decimal digits (skipping any sign prefix).
    let start = s.find(|c: char| c.is_ascii_digit()).unwrap_or(s.len());
    let end = s[start..]
        .find(|c: char| !c.is_ascii_digit())
        .map_or(s.len(), |i| start + i);
    let digit_count = end - start;

    let mut result = String::new();
    result.push_str(&s[..start]);
    for (i, ch) in s[start..end].chars().enumerate() {
        result.push(ch);
        let remaining = digit_count - 1 - i;
        if remaining > 0 && remaining.is_multiple_of(3) {
            result.push('_');
        }
    }
    result.push_str(&s[end..]);
    result
}

#[cfg(test)]
mod tests {
    use super::separate_with_underscores;

    #[test]
    fn groups_digits_in_threes_from_the_right() {
        assert_eq!(separate_with_underscores(0_u64), "0");
        assert_eq!(separate_with_underscores(12_u64), "12");
        assert_eq!(separate_with_underscores(999_u64), "999");
        assert_eq!(separate_with_underscores(1000_u64), "1_000");
        assert_eq!(separate_with_underscores(1234567_u64), "1_234_567");
        assert_eq!(
            separate_with_underscores(1_000_000_000_000_u128),
            "1_000_000_000_000"
        );
        assert_eq!(
            separate_with_underscores(u128::MAX),
            "340_282_366_920_938_463_463_374_607_431_768_211_455"
        );
    }

    #[test]
    fn leaves_sign_prefix_and_fraction_untouched() {
        // Only the first run of digits is grouped.
        assert_eq!(separate_with_underscores(-1234567_i64), "-1_234_567");
        assert_eq!(separate_with_underscores(1234.5678_f64), "1_234.5678");
    }
}
