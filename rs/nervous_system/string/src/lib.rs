use std::fmt::Debug;

/// Returns a possibly modified version of s that fits within the specified bounds.
///
/// More precisely, middle characters are removed such that the return value is at most max_len.
///
/// This is analogous clamp method on numeric types in that this makes the value bounded.
pub fn clamp_string_len(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    if max_len <= 3 {
        return s[0..max_len].to_string();
    }

    let content_len = max_len - 3;
    let tail_len = content_len / 2;
    let head_len = content_len - tail_len;

    let tail_begin = s.len() - tail_len;
    format!("{}...{}", &s[0..head_len], &s[tail_begin..s.len()])
}

pub fn clamp_debug_len(object: &impl Debug, max_len: usize) -> String {
    clamp_string_len(&format!("{:#?}", object), max_len)
}

#[cfg(test)]
mod tests;
