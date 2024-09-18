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
fn test_clamp_debug_len() {
    #[allow(unused)] // Because Rust does not count Debug as a real user of the `i` field.
    #[derive(Debug)]
    struct S {
        i: i32,
    }

    assert_eq!(&clamp_debug_len(&S { i: 42 }, 100), "S {\n    i: 42,\n}");
}
