use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult, threshold_sig::IcRootOfTrust};

mod sign_utils;

pub use sign_utils::{
    KeyBytesContentType, ecdsa_p256_signature_from_der_bytes, ed25519_public_key_to_der,
    rsa_signature_from_bytes, user_public_key_from_bytes,
};

pub fn verify_basic_sig_by_public_key(
    algorithm_id: AlgorithmId,
    msg: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> CryptoResult<()> {
    use ic_crypto_sha2::Sha256;

    let (public_key_bytes, signature_bytes) = (public_key.to_vec(), signature.to_vec());
    match algorithm_id {
        AlgorithmId::Ed25519 => {
            use ic_crypto_internal_basic_sig_ed25519 as ed25519;

            let public_key = ed25519::types::PublicKeyBytes::try_from(public_key_bytes)?;
            let signature = ed25519::types::SignatureBytes::try_from(signature_bytes)?;
            ed25519::verify(&signature, msg, &public_key)
        }
        AlgorithmId::EcdsaP256 => {
            use ic_crypto_internal_basic_sig_ecdsa_secp256r1 as ecdsa_secp256r1;

            let public_key = ecdsa_secp256r1::types::PublicKeyBytes(public_key_bytes);
            let signature = ecdsa_secp256r1::types::SignatureBytes::try_from(signature_bytes)?;

            // ECDSA CLib impl. does not hash the message (as hash algorithm can vary
            // in ECDSA), so we do it here with SHA256, which is the only
            // supported hash currently.
            let msg_hash = Sha256::hash(msg);
            ecdsa_secp256r1::verify(&signature, &msg_hash, &public_key)
        }
        AlgorithmId::EcdsaSecp256k1 => {
            use ic_crypto_internal_basic_sig_ecdsa_secp256k1 as ecdsa_secp256k1;

            let public_key = ecdsa_secp256k1::types::PublicKeyBytes(public_key_bytes);
            let signature = ecdsa_secp256k1::types::SignatureBytes::try_from(signature_bytes)?;

            // ECDSA CLib impl. does not hash the message (as hash algorithm can vary
            // in ECDSA), so we do it here with SHA256, which is the only
            // supported hash currently.
            let msg_hash = Sha256::hash(msg);
            ecdsa_secp256k1::verify(&signature, &msg_hash, &public_key)
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
