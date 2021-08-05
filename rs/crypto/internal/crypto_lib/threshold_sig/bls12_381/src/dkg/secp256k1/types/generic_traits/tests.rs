use super::*;

#[test]
fn should_redact_ephemeral_secret_key_debug() {
    let esk = EphemeralSecretKey(libsecp256k1::curve::Scalar([1u32; 8]));
    assert_eq!(format!("{:?}", esk), "REDACTED");
}

#[test]
fn should_redact_ephemeral_secret_key_bytes_debug() {
    let eskb = EphemeralSecretKeyBytes([1u8; EphemeralSecretKeyBytes::SIZE]);
    assert_eq!(format!("{:?}", eskb), "REDACTED");
}

#[test]
fn should_redact_encrypted_share_bytes_debug() {
    let esb = EncryptedShareBytes([1u8; EncryptedShareBytes::SIZE]);
    assert_eq!(format!("{:?}", esb), "REDACTED");
}
