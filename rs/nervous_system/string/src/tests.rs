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
