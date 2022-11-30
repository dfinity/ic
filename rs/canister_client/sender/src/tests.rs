use super::SigKeys;

pub mod vectors {
    /// A valid secp256k1 key.
    pub const SAMPLE_SECP256K1_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJQhkGfs2ep0VGU5BgJvcc4NVWG0GCc+aqkH7b3DL6aZoAcGBSuBBAAK
oUQDQgAENBexvaA6VKI60UxeTDHiocVBcf+y/irJOHzvQSlwiZM3MCDu6lxaP/Bw
i389XZmdlKFbsLkUI9dDQgMP98YnUA==
-----END EC PRIVATE KEY-----
"#;
    /// A valid ed25519 key is not a valid secp256k1 key.
    pub const SAMPLE_ED25519_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEINnNqExaiF2FFeXR+bDJauDj5XqsXf1505PB13sao+5w
oSMDIQAIrnx74vkGz1A8ngguuFX7B2VfCEjTL4bCnaSrvFNwMA==
-----END PRIVATE KEY-----
"#;
    /// An invalid PEM file; the base64 is valid for secp256k1 but section names don't match.
    pub const SECP256K1_WITH_INVALID_SECTION_NAME: &str = r#"-----BEGIN PRIVATE KEY-----
MHQCAQEEIJQhkGfs2ep0VGU5BgJvcc4NVWG0GCc+aqkH7b3DL6aZoAcGBSuBBAAK
oUQDQgAENBexvaA6VKI60UxeTDHiocVBcf+y/irJOHzvQSlwiZM3MCDu6lxaP/Bw
i389XZmdlKFbsLkUI9dDQgMP98YnUA==
-----END PRIVATE KEY-----
"#;
    /// An invalid pem; the base64 is invalid.
    ///
    /// (A trailing A== is missing from the base64 of an otherwse valid secp256k1 key.)
    pub const SAMPLE_MALFORMED_BASE64: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJQhkGfs2ep0VGU5BgJvcc4NVWG0GCc+aqkH7b3DL6aZoAcGBSuBBAAK
oUQDQgAENBexvaA6VKI60UxeTDHiocVBcf+y/irJOHzvQSlwiZM3MCDu6lxaP/Bw
i389XZmdlKFbsLkUI9dDQgMP98YnU
-----END EC PRIVATE KEY-----
"#;
    /// An ed25519 key in a pem section matching secp256k1 should fail to parse.
    pub const SAMPLE_WITH_ED25519_PAYLOAD: &str = r#"-----BEGIN EC PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEINnNqExaiF2FFeXR+bDJauDj5XqsXf1505PB13sao+5w
oSMDIQAIrnx74vkGz1A8ngguuFX7B2VfCEjTL4bCnaSrvFNwMA==
-----END EC PRIVATE KEY-----
"#;
}

#[test]
fn should_parse_secp256k1_pem() {
    SigKeys::from_pem(vectors::SAMPLE_SECP256K1_PEM).expect("failed to read secp256k1 key");
}
#[test]
fn should_parse_ed25519_pem() {
    SigKeys::from_pem(vectors::SAMPLE_ED25519_PEM).expect("failed to read ed25519 key");
}
#[test]
fn should_fail_to_read_key_with_wrong_section_title() {
    SigKeys::from_pem(vectors::SECP256K1_WITH_INVALID_SECTION_NAME)
        .map(|_| ())
        .expect_err("secp256k1 parser should require 'EC PRIVATE KEY'.");
}
#[test]
fn should_fail_to_read_key_with_invalid_base64() {
    SigKeys::from_pem(vectors::SAMPLE_MALFORMED_BASE64)
        .map(|_| ())
        .expect_err("Pem should require valid base 64.");
}
#[test]
fn should_fail_to_read_key_for_wrong_curve() {
    SigKeys::from_pem(vectors::SAMPLE_WITH_ED25519_PAYLOAD)
        .map(|_| ())
        .expect_err("The base64 payload should be a secp256k1 key");
}
