//! Signature utilities
use ic_crypto_internal_basic_sig_cose as cose;
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_crypto_internal_basic_sig_ecdsa_secp256k1 as ecdsa_secp256k1;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1 as ecdsa_secp256r1;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_basic_sig_iccsa as iccsa;
use ic_crypto_internal_basic_sig_rsa_pkcs1 as rsa;
use ic_types::crypto::{AlgorithmId, BasicSig, CryptoError, CryptoResult, UserPublicKey};

/// Indicates the content type of serialised key bytes passed for parsing.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum KeyBytesContentType {
    Ed25519PublicKeyDer,
    EcdsaP256PublicKeyDer,
    EcdsaSecp256k1PublicKeyDer,
    RsaSha256PublicKeyDer,
    EcdsaP256PublicKeyDerWrappedCose,
    RsaSha256PublicKeyDerWrappedCose,
    IcCanisterSignatureAlgPublicKeyDer,
}

fn cose_key_bytes_content_type(alg_id: AlgorithmId) -> Option<KeyBytesContentType> {
    match alg_id {
        AlgorithmId::EcdsaP256 => Some(KeyBytesContentType::EcdsaP256PublicKeyDerWrappedCose),
        AlgorithmId::RsaSha256 => Some(KeyBytesContentType::RsaSha256PublicKeyDerWrappedCose),
        _ => None,
    }
}

/// Parses the given `bytes` as a DER-encoded public key, and returns, if the
/// parsing is successful, the key as `UserPublicKey`-struct and an enum that
/// indicates the content type of the passed `bytes`.  If parsing fails, returns
/// an error.
pub fn user_public_key_from_bytes(
    bytes: &[u8],
) -> CryptoResult<(UserPublicKey, KeyBytesContentType)> {
    let (pkix_algo_id, pk_bytes) = der_utils::algo_id_and_public_key_bytes_from_der(bytes)
        .map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Placeholder,
            key_bytes: Some(bytes.to_vec()),
            internal_error: e.internal_error,
        })?;

    let (key, algorithm_id, content_type) = if pkix_algo_id == ed25519::api::algorithm_identifier()
    {
        (
            ed25519::api::public_key_from_der(bytes)?.0.to_vec(),
            AlgorithmId::Ed25519,
            KeyBytesContentType::Ed25519PublicKeyDer,
        )
    } else if pkix_algo_id == ecdsa_secp256k1::algorithm_identifier() {
        (
            ecdsa_secp256k1::api::public_key_from_der(bytes)?.0,
            AlgorithmId::EcdsaSecp256k1,
            KeyBytesContentType::EcdsaSecp256k1PublicKeyDer,
        )
    } else if pkix_algo_id == ecdsa_secp256r1::algorithm_identifier() {
        (
            ecdsa_secp256r1::public_key_from_der(bytes)?.0,
            AlgorithmId::EcdsaP256,
            KeyBytesContentType::EcdsaP256PublicKeyDer,
        )
    } else if pkix_algo_id == cose::algorithm_identifier() {
        let (alg_id, bytes) = cose::parse_cose_public_key(&pk_bytes)?;
        let key_bytes = user_public_key_from_bytes(&bytes)?;
        let key_contents_type = cose_key_bytes_content_type(alg_id).ok_or_else(|| {
            CryptoError::AlgorithmNotSupported {
                algorithm: alg_id,
                reason: "cose_key_bytes_content_type needs to be updated for this algorithm"
                    .to_string(),
            }
        })?;
        (key_bytes.0.key, alg_id, key_contents_type)
    } else if pkix_algo_id == iccsa::algorithm_identifier() {
        (
            iccsa::public_key_bytes_from_der(bytes)?.0,
            AlgorithmId::IcCanisterSignature,
            KeyBytesContentType::IcCanisterSignatureAlgPublicKeyDer,
        )
    } else if pkix_algo_id == rsa::algorithm_identifier() {
        (
            rsa::RsaPublicKey::from_der_spki(bytes)?.as_der().to_vec(),
            AlgorithmId::RsaSha256,
            KeyBytesContentType::RsaSha256PublicKeyDer,
        )
    } else {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Placeholder,
            key_bytes: Some(bytes.to_vec()),
            internal_error: "Unsupported or unparsable public key".to_string(),
        });
    };

    Ok((UserPublicKey { key, algorithm_id }, content_type))
}

/// Encodes a raw ed25519 public key into DER.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey`: if the raw public key is malformed.
pub fn ed25519_public_key_to_der(raw_key: Vec<u8>) -> CryptoResult<Vec<u8>> {
    let key: [u8; 32] = raw_key.as_slice().try_into().map_err(|_| {
        let key_length = raw_key.len();
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: Some(raw_key),
            internal_error: format!(
                "Incorrect length. Expected 32 bytes but found {} bytes",
                key_length
            ),
        }
    })?;

    Ok(ed25519::public_key_to_der(ed25519::types::PublicKeyBytes(
        key,
    )))
}

/// Decodes an ECDSA P-256 signature from DER.
///
/// # Errors
/// * `CryptoError::MalformedSignature`: if the signature cannot be DER decoded.
pub fn ecdsa_p256_signature_from_der_bytes(bytes: &[u8]) -> CryptoResult<BasicSig> {
    let ecdsa_sig = ecdsa_secp256r1::signature_from_der(bytes)?;
    Ok(BasicSig(ecdsa_sig.0.to_vec()))
}

/// Decodes an RSA signature from binary data.
pub fn rsa_signature_from_bytes(bytes: &[u8]) -> BasicSig {
    BasicSig(bytes.to_vec())
}
