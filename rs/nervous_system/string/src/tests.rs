use super::*;

#[test]
fn test_clamp_string_len() {
    assert_eq!(&clamp_string_len("123456789", 0), "");
    assert_eq!(&clamp_string_len("123456789", 1), "1");
    assert_eq!(&clamp_string_len("123456789", 2), "12");
    assert_eq!(&clamp_string_len("123456789", 3), "123");
    assert_eq!(&clamp_string_len("123456789", 4), "1...");
    assert_eq!(&clamp_string_len("123456789", 5), "1...9");
    assert_eq!(&clamp_string_len("123456789", 6), "12...9");
    assert_eq!(&clamp_string_len("123456789", 7), "12...89");
    assert_eq!(&clamp_string_len("123456789", 8), "123...89");
    assert_eq!(&clamp_string_len("123456789", 9), "123456789");
    assert_eq!(&clamp_string_len("123456789", 10), "123456789");
    assert_eq!(&clamp_string_len("123456789", 11), "123456789");
}

#[test]
fn test_clamp_string_corner_cases() {
    for (s, max_len, expected) in [
        ("abcdef", usize::MAX, "abcdef"),
        ("abcdef", 10, "abcdef"),
        ("abcdef", 5, "a...f"),
        ("abcde", 5, "abcde"),
        ("abcd", 5, "abcd"),
        ("abcde", 4, "a..."),
        ("abcd", 4, "abcd"),
        ("abcd", 3, "abc"),
        ("abcd", 2, "ab"),
        ("abcd", 1, "a"),
        ("abcd", 0, ""),
        ("", 5, ""),
        ("", 0, ""),
        ("\u{200D}\u{200D}\u{200D}", 2, "\u{200d}\u{200d}"),
        ("🙂🗜🌟🚀", 4, "🙂🗜🌟🚀"),
        ("🙂🗜🌟🚀", 3, "🙂🗜🌟"),
        ("🙂🗜🌟🚀", 2, "🙂🗜"),
        ("🙂🗜🌟🚀", 1, "🙂"),
        ("你好, 世界", 5, "你...界"),
    ] {
        assert_eq!(
            clamp_string_len(s, max_len),
            expected.to_string(),
            "clamp_string_len({s}, {max_len}) returned an unexpected value.",
        );
    }
}

#[test]
fn test_clamp_debug_len() {
    #[allow(unused)] // Because Rust does not count Debug as a real user of the `i` field.
    #[derive(Debug)]
    struct S {
        i: i32,
    }

    assert_eq!(&clamp_debug_len(&S { i: 42 }, 100), "S {\n    i: 42,\n}");
}

#[test]
fn test_clamp_debug_len_truncation() {
    #[allow(unused)]
    #[derive(Debug)]
    struct S {
        i: i32,
    }

    // Truncation: the full debug output is "S {\n    i: 42,\n}" (16 chars).
    // With max_len=10, we get 10 chars with the last 3 replaced by "...".
    assert_eq!(&clamp_debug_len(&S { i: 42 }, 10), "S {\n   ...");

    // Very small limit.
    assert_eq!(&clamp_debug_len(&S { i: 42 }, 3), "...");
}

#[test]
fn test_clamp_debug_len_large_object() {
    // Verify that clamp_debug_len doesn't format the entire object
    // when truncating. We can't easily prove this in a unit test, but
    // we can verify the output is correct for a large-ish object.
    let big_vec: Vec<i32> = (0..10_000).collect();
    let result = clamp_debug_len(&big_vec, 50);
    assert!(result.len() <= 50, "result len: {}", result.len());
    assert!(result.ends_with("..."), "result: {result}");
}

#[test]
fn test_humanize_blob() {
    // Short blob: fully hex-encoded.
    assert_eq!(humanize_blob(&[0x00, 0x61, 0x73, 0x6d], 10), "0061736d");

    // Exact boundary.
    assert_eq!(humanize_blob(&[0xab, 0xcd], 2), "abcd");

    // Truncated.
    assert_eq!(
        humanize_blob(&[0xab, 0xcd, 0xef], 2),
        "abcd... (3 bytes total)",
    );

    // Empty.
    assert_eq!(humanize_blob(&[], 10), "");
}
