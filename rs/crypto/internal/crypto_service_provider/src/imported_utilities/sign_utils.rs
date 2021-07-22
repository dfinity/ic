//! Signature utilities
use crate::types::CspSignature;
use ic_crypto_internal_basic_sig_cose as cose;
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_crypto_internal_basic_sig_ecdsa_secp256k1 as ecdsa_secp256k1;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1 as ecdsa_secp256r1;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_basic_sig_iccsa as iccsa;
use ic_crypto_internal_basic_sig_rsa_pkcs1 as rsa;
use ic_crypto_internal_threshold_sig_bls12381 as bls12_381;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes as BlsPublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_interfaces::crypto::Signable;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{
    AlgorithmId, BasicSig, CombinedThresholdSig, CombinedThresholdSigOf, CryptoError, CryptoResult,
    UserPublicKey,
};
use ic_types::{NumberOfNodes, Randomness};
use std::convert::{TryFrom, TryInto};

#[cfg(test)]
mod tests;

/// Indicates the content type of serialised key bytes passed for parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyBytesContentType {
    Ed25519PublicKeyDer,
    EcdsaP256PublicKeyDer,
    EcdsaSecp256k1PublicKeyDer,
    RsaSha256PublicKeyDer,
    EcdsaP256PublicKeyDerWrappedCose,
    RsaSha256PublicKeyDerWrappedCose,
    IcCanisterSignatureAlgPublicKeyDer,
}

fn cose_key_bytes_content_type(alg_id: AlgorithmId) -> CryptoResult<KeyBytesContentType> {
    if alg_id == AlgorithmId::EcdsaP256 {
        Ok(KeyBytesContentType::EcdsaP256PublicKeyDerWrappedCose)
    } else if alg_id == AlgorithmId::RsaSha256 {
        Ok(KeyBytesContentType::RsaSha256PublicKeyDerWrappedCose)
    } else {
        Err(CryptoError::AlgorithmNotSupported {
            algorithm: alg_id,
            reason: "cose_key_bytes_content_type needs to be updated for this algorithm"
                .to_string(),
        })
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
            ecdsa_secp256r1::api::public_key_from_der(bytes)?.0,
            AlgorithmId::EcdsaP256,
            KeyBytesContentType::EcdsaP256PublicKeyDer,
        )
    } else if pkix_algo_id == cose::algorithm_identifier() {
        let (alg_id, bytes) = cose::parse_cose_public_key(&pk_bytes)?;
        let key_bytes = user_public_key_from_bytes(&bytes)?;
        let key_contents_type = cose_key_bytes_content_type(alg_id)?;
        (key_bytes.0.key, alg_id, key_contents_type)
    } else if pkix_algo_id == iccsa::algorithm_identifier() {
        (
            iccsa::api::public_key_bytes_from_der(bytes)?.0,
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
            internal_error: "Unsupported or unparseable public key".to_string(),
        });
    };

    Ok((UserPublicKey { key, algorithm_id }, content_type))
}

/// Decodes an ECDSA P-256 signature from DER.
///
/// # Errors
/// * `CryptoError::MalformedSignature`: if the signature cannot be DER decoded.
pub fn ecdsa_p256_signature_from_der_bytes(bytes: &[u8]) -> CryptoResult<BasicSig> {
    let ecdsa_sig = ecdsa_secp256r1::api::signature_from_der(bytes)?;
    Ok(BasicSig(ecdsa_sig.0.to_vec()))
}

/// Encodes a threshold signature public key into DER.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey`: if the public cannot be DER encoded.
pub fn threshold_sig_public_key_to_der(pk: ThresholdSigPublicKey) -> CryptoResult<Vec<u8>> {
    // TODO(CRP-641): add a check that the key is indeed a BLS key.
    let pk = BlsPublicKeyBytes(pk.into_bytes());
    bls12_381::api::public_key_to_der(pk)
}

/// Decodes a threshold signature public key from DER.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey`: if the public cannot be DER decoded.
pub fn threshold_sig_public_key_from_der(bytes: &[u8]) -> CryptoResult<ThresholdSigPublicKey> {
    let pk = bls12_381::api::public_key_from_der(bytes)?;
    Ok(pk.into())
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

/// Decodes an RSA signature from binary data.
pub fn rsa_signature_from_bytes(bytes: &[u8]) -> BasicSig {
    BasicSig(bytes.to_vec())
}

/// Verifies a combined threshold signature.
// TODO(CRP-622): remove this helper once crypto has NNS-verification built in.
#[allow(dead_code)]
pub fn verify_combined_threshold_sig<T: Signable>(
    msg: &T,
    sig: &CombinedThresholdSigOf<T>,
    pk: &ThresholdSigPublicKey,
) -> CryptoResult<()> {
    let bls_pk = BlsPublicKeyBytes(pk.into_bytes());
    let csp_sig = CspSignature::try_from(sig)?;
    if csp_sig.algorithm() != AlgorithmId::ThresBls12_381 {
        return Err(CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: vec![],
            internal_error: "Not a ThresBls12_381-signature".to_string(),
        });
    }
    let bls_sig = bls12_381::types::CombinedSignatureBytes::try_from(csp_sig)?;
    bls12_381::api::verify_combined_signature(&msg.as_signed_bytes(), bls_sig, bls_pk)
}

/// Creates a combined threshold signature together with its public key. This is
/// only used for testing.
// TODO(CRP-622): consider turning it into a test_util once crypto has
// NNS-verfification built in.
#[allow(dead_code)]
pub fn combined_threshold_signature_and_public_key<T: Signable>(
    seed: Randomness,
    message: &T,
) -> (CombinedThresholdSigOf<T>, ThresholdSigPublicKey) {
    let group_size = 1;
    let threshold = NumberOfNodes::new(1);
    let (signature, public_key) = bls12_381::api::combined_signature_and_public_key(
        seed,
        group_size,
        threshold,
        &message.as_signed_bytes(),
    );
    (
        CombinedThresholdSigOf::from(CombinedThresholdSig(signature.0.to_vec())),
        ThresholdSigPublicKey::from(CspThresholdSigPublicKey::from(public_key)),
    )
}
