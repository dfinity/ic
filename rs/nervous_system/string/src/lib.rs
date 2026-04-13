use std::fmt::{self, Debug, Write};

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

/// Formats object, but limits the output size.
///
/// Unlike clamp_string_len, does not include the tail (when truncating).
pub fn clamp_debug_len(object: &impl Debug, max_len: usize) -> String {
    let mut buf = LimitedWriter::new(max_len);
    // write! returns Err if the writer returns Err, which LimitedWriter does
    // once the limit is hit. We intentionally ignore this "error".
    let _ignore_err = write!(buf, "{object:#?}");

    if buf.truncated {
        // Replace the last 3 chars with "..." to indicate truncation,
        // or just append if the string is very short.
        let s = &mut buf.buffer;
        if s.len() >= 3 {
            for _ in 0..3 {
                s.pop();
            }
        }
        s.push_str("...");
    }

    buf.buffer
}

/// A `fmt::Write` implementation that stops accepting characters after a limit.
struct LimitedWriter {
    buffer: String,
    remaining: usize,
    truncated: bool,
}

impl LimitedWriter {
    fn new(max_len: usize) -> Self {
        Self {
            buffer: String::with_capacity(max_len.min(1024)),
            remaining: max_len,
            truncated: false,
        }
    }
}

impl fmt::Write for LimitedWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.remaining == 0 {
            self.truncated = true;
            return Err(fmt::Error);
        }

        let chars_available = self.remaining;
        let mut char_count = 0;
        let byte_limit = s
            .char_indices()
            .take_while(|(_, _)| {
                char_count += 1;
                char_count <= chars_available
            })
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);

        if byte_limit < s.len() {
            self.buffer.push_str(&s[..byte_limit]);
            self.remaining = 0;
            self.truncated = true;
            Err(fmt::Error)
        } else {
            self.buffer.push_str(s);
            self.remaining -= char_count;
            Ok(())
        }
    }
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
