use super::*;

#[test]
fn should_redact_secret_key_bytes_debug() {
    let secret_key = SecretKeyBytes([1u8; SecretKeyBytes::SIZE]);
    let debug_str = format!("{:?}", secret_key);
    assert_eq!(debug_str, "REDACTED");
}
