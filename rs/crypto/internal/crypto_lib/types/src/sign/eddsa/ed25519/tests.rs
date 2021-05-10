use super::*;

#[test]
fn should_redact_secret_key_bytes_debug() {
    let secret_key = SecretKey([1u8; SecretKey::SIZE]);
    let debug_str = format!("{:?}", secret_key);
    assert_eq!(debug_str, "REDACTED");
}
