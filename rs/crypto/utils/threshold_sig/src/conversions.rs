use ic_crypto_internal_threshold_sig_bls12381 as bls12_381;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// Parse a PEM format threshold signature public key from a named file.
///
/// # Arguments
/// * `pem_file` names the filesystem path where the key to be read from is
///   located.
/// # Returns
/// The decoded `ThresholdSigPublicKey`
/// # Error
/// * `std::io::Error` if the file cannot be opened, or if the contents
/// are not PEM, or if the encoded key is not BLS12-381.
pub fn parse_threshold_sig_key(pem_file: &Path) -> Result<ThresholdSigPublicKey> {
    fn invalid_data_err(msg: impl std::string::ToString) -> Error {
        Error::new(ErrorKind::InvalidData, msg.to_string())
    }

    let buf = std::fs::read(pem_file)?;
    let s = String::from_utf8_lossy(&buf);
    let lines: Vec<_> = s.trim_end().lines().collect();
    let n = lines.len();

    if n < 3 {
        return Err(invalid_data_err("input file is too short"));
    }

    if !lines[0].starts_with("-----BEGIN PUBLIC KEY-----") {
        return Err(invalid_data_err(
            "PEM file doesn't start with 'BEGIN PUBLIC KEY' block",
        ));
    }
    if !lines[n - 1].starts_with("-----END PUBLIC KEY-----") {
        return Err(invalid_data_err(
            "PEM file doesn't end with 'END PUBLIC KEY' block",
        ));
    }

    let decoded = base64::decode(&lines[1..n - 1].join(""))
        .map_err(|err| invalid_data_err(format!("failed to decode base64: {}", err)))?;

    let pubkey_bytes = bls12_381::api::public_key_from_der(&decoded)
        .map_err(|err| invalid_data_err(format!("failed to decode public key: {}", err)))?;

    Ok(ThresholdSigPublicKey::from(pubkey_bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn can_parse_pem_file() {
        use std::io::Write;

        let contents = r#"-----BEGIN PUBLIC KEY-----
MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKOY3Qk9qTesCRaL
GY4Bb/WQ5wfxhiUca4hbVIRfOkPlNtXSg/AHff5QIckWPifeyRB/S9A1jjg1XdKP
5lSemYM6VVTrGhjShUwHqVmdOBJ8ofpb2+qV/2ppvxc+3OFBvA==
-----END PUBLIC KEY-----
"#;

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(contents.as_bytes()).unwrap();
        let pk = parse_threshold_sig_key(tmpfile.path()).unwrap();
        assert_eq!(
        hex::encode(&pk.into_bytes()[..]),
        "a398dd093da937ac09168b198e016ff590e707f186251c6b885b54845f3a43e536d5d283f0077dfe5021c9163e27dec9107f4bd0358e38355dd28fe6549e99833a5554eb1a18d2854c07a9599d38127ca1fa5bdbea95ff6a69bf173edce141bc"
    );
    }

    #[test]
    fn base64_decode_fails() {
        use std::io::Write;

        let contents = r#"-----BEGIN PUBLIC KEY-----
MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKOY3Qk9qTesCRaL
GY4Bb/WQ5wfxhiUca4hbVIRfOkPlNtXSg/AHff5QIckWPifeyRB/S9A1jjg1XdKP
5lSemYM6VVTGhjShUwHqVmdOBJ8ofpb2+qV/2ppvxc+3OFBvA==
-----END PUBLIC KEY-----
"#;

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(contents.as_bytes()).unwrap();
        let pk = parse_threshold_sig_key(tmpfile.path());
        assert!(pk.is_err());
    }
}
