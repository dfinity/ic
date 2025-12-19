use crate::{public_key_from_der, public_key_to_der};
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use std::path::Path;
use thiserror::Error;

/// An error returned when converting a threshold signature public key
/// to or from various formats (PEM, DER, raw bytes).
#[derive(Clone, Debug, Error)]
pub enum KeyConversionError {
    /// Failed to read the key file.
    #[error("Failed to read key file: {0}")]
    IoError(String),
    /// The PEM encoding is invalid.
    #[error("Invalid PEM encoding: {0}")]
    InvalidPem(String),
    /// The DER encoding is invalid or decoding failed.
    #[error("Invalid DER encoding: {0}")]
    InvalidDer(String),
    /// Failed to encode the key to DER format.
    #[error("Failed to encode key to DER: {0}")]
    DerEncoding(String),
}

/// Parse a PEM format threshold signature public key from a named file.
///
/// # Arguments
/// * `pem_file` names the filesystem path where the key to be read from is
///   located.
/// # Returns
/// The decoded `ThresholdSigPublicKey`
/// # Error
/// * `KeyConversionError` if the file cannot be opened, or if the contents
///   are not PEM, or if the encoded key is not BLS12-381.
pub fn parse_threshold_sig_key_from_pem_file(
    pem_file: &Path,
) -> Result<ThresholdSigPublicKey, KeyConversionError> {
    let buf = std::fs::read(pem_file).map_err(|e| KeyConversionError::IoError(e.to_string()))?;
    let pem = pem::parse(&buf).map_err(|e| KeyConversionError::InvalidPem(format!("{e:?}")))?;

    if pem.tag() != "PUBLIC KEY" {
        return Err(KeyConversionError::InvalidPem(format!(
            "expected 'PUBLIC KEY' tag, got '{}'",
            pem.tag()
        )));
    }

    parse_threshold_sig_key_from_der(pem.contents())
}

/// Parse a DER format threshold signature public key from bytes.
///
/// # Arguments
/// * `der_bytes` DER encoded public key
/// # Returns
/// The decoded `ThresholdSigPublicKey`
/// # Error
/// * `KeyConversionError` if the data cannot be parsed, or if the encoded key is not BLS12-381.
pub fn parse_threshold_sig_key_from_der(
    der_bytes: &[u8],
) -> Result<ThresholdSigPublicKey, KeyConversionError> {
    let pk_bytes = public_key_from_der(der_bytes).map_err(KeyConversionError::InvalidDer)?;
    Ok(ThresholdSigPublicKey::from(PublicKeyBytes(pk_bytes)))
}

/// Encodes a threshold signature public key into DER.
///
/// # Errors
/// * `KeyConversionError::DerEncoding`: if the public key cannot be DER encoded.
pub fn threshold_sig_public_key_to_der(
    pk: ThresholdSigPublicKey,
) -> Result<Vec<u8>, KeyConversionError> {
    let key = PublicKeyBytes(pk.into_bytes());
    public_key_to_der(&key.0).map_err(KeyConversionError::DerEncoding)
}

/// Encodes a threshold signature public key into PEM format.
///
/// # Errors
/// * `KeyConversionError::DerEncoding`: if the public key cannot be encoded.
pub fn threshold_sig_public_key_to_pem(
    pk: ThresholdSigPublicKey,
) -> Result<Vec<u8>, KeyConversionError> {
    let der_bytes = threshold_sig_public_key_to_der(pk)?;
    Ok(public_key_der_to_pem(&der_bytes))
}

/// Encodes DER-encoded public key bytes into PEM format.
pub fn public_key_der_to_pem(der_bytes: &[u8]) -> Vec<u8> {
    pem::encode_config(
        &pem::Pem::new("PUBLIC KEY", der_bytes),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
    .into_bytes()

    //pem::encode(&pem::Pem::new("PUBLIC KEY", der_bytes)).into_bytes()
}
