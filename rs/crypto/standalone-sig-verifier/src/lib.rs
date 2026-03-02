use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult, threshold_sig::IcRootOfTrust};

mod algorithm_identifiers;
mod sign_utils;

pub use sign_utils::{
    KeyBytesContentType, ecdsa_p256_signature_from_der_bytes, ed25519_public_key_to_der,
    rsa_signature_from_bytes, user_public_key_from_bytes,
};

pub fn verify_basic_sig_by_public_key(
    algorithm_id: AlgorithmId,
    msg: &[u8],
    sig: &[u8],
    pk_bytes: &[u8],
) -> CryptoResult<()> {
    let (public_key_bytes, signature_bytes) = (pk_bytes.to_vec(), sig.to_vec());

    match algorithm_id {
        AlgorithmId::Ed25519 => {
            let pk = ic_ed25519::PublicKey::deserialize_raw(pk_bytes).map_err(|e| {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::Ed25519,
                    key_bytes: Some(pk_bytes.to_vec()),
                    internal_error: e.to_string(),
                }
            })?;

            if sig.len() != ic_ed25519::SIGNATURE_BYTES {
                return Err(CryptoError::MalformedSignature {
                    algorithm: AlgorithmId::Ed25519,
                    sig_bytes: sig.to_vec(),
                    internal_error: "Invalid length".to_string(),
                });
            }

            pk.verify_signature(msg, sig)
                .map_err(|e| CryptoError::SignatureVerification {
                    algorithm: AlgorithmId::Ed25519,
                    public_key_bytes: pk.serialize_raw().to_vec(),
                    sig_bytes: sig.to_vec(),
                    internal_error: e.to_string(),
                })
        }
        AlgorithmId::EcdsaP256 => {
            let pk = ic_secp256r1::PublicKey::deserialize_sec1(pk_bytes).map_err(|e| {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::EcdsaP256,
                    key_bytes: Some(pk_bytes.to_vec()),
                    internal_error: format!("{e:?}"),
                }
            })?;

            if sig.len() != 64 {
                return Err(CryptoError::MalformedSignature {
                    algorithm: AlgorithmId::EcdsaP256,
                    sig_bytes: sig.to_vec(),
                    internal_error: "Invalid length".to_string(),
                });
            }

            if pk.verify_signature(msg, sig) {
                Ok(())
            } else {
                Err(CryptoError::SignatureVerification {
                    algorithm: AlgorithmId::EcdsaP256,
                    public_key_bytes: pk.serialize_sec1(false).to_vec(),
                    sig_bytes: sig.to_vec(),
                    internal_error: "Invalid signature".to_string(),
                })
            }
        }
        AlgorithmId::EcdsaSecp256k1 => {
            let pk = ic_secp256k1::PublicKey::deserialize_sec1(pk_bytes).map_err(|e| {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::EcdsaSecp256k1,
                    key_bytes: Some(pk_bytes.to_vec()),
                    internal_error: format!("{e:?}"),
                }
            })?;

            if sig.len() != 64 {
                return Err(CryptoError::MalformedSignature {
                    algorithm: AlgorithmId::EcdsaSecp256k1,
                    sig_bytes: sig.to_vec(),
                    internal_error: "Invalid length".to_string(),
                });
            }

            if pk.verify_signature(msg, sig) {
                Ok(())
            } else {
                Err(CryptoError::SignatureVerification {
                    algorithm: AlgorithmId::EcdsaSecp256k1,
                    public_key_bytes: pk.serialize_sec1(false).to_vec(),
                    sig_bytes: sig.to_vec(),
                    internal_error: "Invalid signature".to_string(),
                })
            }
        }
        AlgorithmId::RsaSha256 => {
            use ic_crypto_internal_basic_sig_rsa_pkcs1 as rsa;

            let public_key = rsa::RsaPublicKey::from_der_spki(&public_key_bytes)?;

            // RSA hashes the message using SHA-256
            public_key.verify_pkcs1_sha256(msg, &signature_bytes)
        }
        algorithm => Err(CryptoError::AlgorithmNotSupported {
            algorithm,
            reason: "Not supported for basic signature verification".to_string(),
        }),
    }
}

pub fn verify_canister_sig<R: AsRef<IcRootOfTrust>>(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    root_of_trust: R,
) -> CryptoResult<()> {
    use ic_crypto_iccsa as iccsa;

    iccsa::verify(
        message,
        iccsa::types::SignatureBytes(signature.to_vec()),
        iccsa::types::PublicKeyBytes(public_key.to_vec()),
        root_of_trust.as_ref().as_ref(),
    )
}
