use std::fmt::Debug;

/// Returns a possibly modified version of `s` that fits within the specified bounds (in terms of
/// the number of UTF-8 characters).
///
/// More precisely, middle characters are removed such that the return value has at most `max_len`
/// characters. Some examples:
/// ```
/// use ic_nervous_system_string::clamp_string_len;
/// println!("{}", clamp_string_len("abcdef", 5));  // a...f
/// println!("{}", clamp_string_len("abcde", 5));   // abcde
/// println!("{}", clamp_string_len("abcd", 5));    // abcd
/// ```
///
/// This is analogous clamp method on numeric types in that this makes the value bounded.
pub fn clamp_string_len(s: &str, max_len: usize) -> String {
    // Collect into a vector so that we can safely index the input.
    let chars: Vec<_> = s.chars().collect();
    if max_len <= 3 {
        return chars.into_iter().take(max_len).collect();
    }

    if chars.len() <= max_len {
        return s.to_string();
    }

    let ellipsis = "...";
    let content_len = max_len - ellipsis.len();
    let tail_len = content_len / 2;
    let head_len = content_len - tail_len;
    let tail_begin = chars.len() - tail_len;

    format!(
        "{}{}{}",
        chars[..head_len].iter().collect::<String>(),
        ellipsis,
        chars[tail_begin..].iter().collect::<String>(),
    )
}

pub fn clamp_debug_len(object: &impl Debug, max_len: usize) -> String {
    clamp_string_len(&format!("{object:#?}"), max_len)
}

/// Hex-encodes bytes, truncating with a summary if longer than `max_bytes`.
pub fn humanize_blob(bytes: &[u8], max_bytes: usize) -> String {
    if bytes.len() <= max_bytes {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    } else {
        let hex: String = bytes[..max_bytes]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{hex}... ({} bytes total)", bytes.len())
    }
}

#[cfg(test)]
mod tests;
