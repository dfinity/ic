use crate::{public_key_from_der, public_key_to_der};
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
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
///   are not PEM, or if the encoded key is not BLS12-381.
pub fn parse_threshold_sig_key(pem_file: &Path) -> Result<ThresholdSigPublicKey> {
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

    let decoded = base64::decode(lines[1..n - 1].join(""))
        .map_err(|err| invalid_data_err(format!("failed to decode base64: {err}")))?;

    parse_threshold_sig_key_from_der(&decoded)
}

/// Parse a DER format threshold signature public key from bytes.
///
/// # Arguments
/// * `der_bytes` DER encoded public key
/// # Returns
/// The decoded `ThresholdSigPublicKey`
/// # Error
/// * `std::io::Error` if the data cannot be parsed, or if the encoded key is not BLS12-381.
pub fn parse_threshold_sig_key_from_der(der_bytes: &[u8]) -> Result<ThresholdSigPublicKey> {
    let pk_bytes = match public_key_from_der(der_bytes) {
        Ok(key_bytes) => PublicKeyBytes(key_bytes),
        Err(internal_error) => {
            return Err(invalid_data_err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::ThresBls12_381,
                key_bytes: Some(der_bytes.to_vec()),
                internal_error,
            }));
        }
    };
    Ok(ThresholdSigPublicKey::from(pk_bytes))
}

/// Encodes a threshold signature public key into DER.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey`: if the public cannot be DER encoded.
pub fn threshold_sig_public_key_to_der(pk: ThresholdSigPublicKey) -> CryptoResult<Vec<u8>> {
    // TODO(CRP-641): add a check that the key is indeed a BLS key.

    let key = PublicKeyBytes(pk.into_bytes());

    public_key_to_der(&key.0).map_err(|e| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::ThresBls12_381,
        key_bytes: Some(key.0.to_vec()),
        internal_error: format!("Conversion to DER failed with error {e}"),
    })
}

/// Decodes a threshold signature public key from DER.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey`: if the public cannot be DER decoded.
pub fn threshold_sig_public_key_from_der(bytes: &[u8]) -> CryptoResult<ThresholdSigPublicKey> {
    match public_key_from_der(bytes) {
        Ok(key_bytes) => Ok(PublicKeyBytes(key_bytes).into()),
        Err(internal_error) => Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::ThresBls12_381,
            key_bytes: Some(bytes.to_vec()),
            internal_error,
        }),
    }
}

fn invalid_data_err(msg: impl std::string::ToString) -> Error {
    Error::new(ErrorKind::InvalidData, msg.to_string())
}
