use super::api::CspSigner;
use super::types::{CspPop, CspPublicKey, CspSignature};
use super::Csp;
use crate::secret_key_store::SecretKeyStore;
use crate::types::MultiBls12_381_Signature;
use crate::vault::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspMultiSignatureError, MultiSignatureCspVault,
};
use ic_crypto_internal_basic_sig_ecdsa_secp256k1 as ecdsa_secp256k1;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1 as ecdsa_secp256r1;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_multi_sig_bls12381 as multi_sig;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult, KeyId};
use openssl::sha::sha256;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore> CspSigner for Csp<R, S, C> {
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> CryptoResult<CspSignature> {
        match algorithm_id {
            AlgorithmId::Ed25519 => self
                .csp_vault
                .sign(algorithm_id, message, key_id)
                .map_err(CspBasicSignatureError::into),
            AlgorithmId::MultiBls12_381 => self
                .csp_vault
                .multi_sign(algorithm_id, message, key_id)
                .map_err(CspMultiSignatureError::into),
            _ => Err(CryptoError::InvalidArgument {
                message: format!("Cannot sign with unsupported algorithm: {:?}", algorithm_id),
            }),
        }
    }

    fn verify(
        &self,
        sig: &CspSignature,
        msg: &[u8],
        algorithm_id: AlgorithmId,
        signer: CspPublicKey,
    ) -> CryptoResult<()> {
        match (algorithm_id, sig, signer) {
            (
                AlgorithmId::EcdsaP256,
                CspSignature::EcdsaP256(signature),
                CspPublicKey::EcdsaP256(public_key),
            ) => {
                // ECDSA CLib impl. does not hash the message (as hash algorithm can vary
                // in ECDSA), so we do it here with SHA256, which is the only
                // supported hash currently.
                let msg_hash = sha256(msg);
                ecdsa_secp256r1::verify(signature, &msg_hash, &public_key)
            }
            (
                AlgorithmId::EcdsaSecp256k1,
                CspSignature::EcdsaSecp256k1(signature),
                CspPublicKey::EcdsaSecp256k1(public_key),
            ) => {
                // ECDSA CLib impl. does not hash the message (as hash algorithm can vary
                // in ECDSA), so we do it here with SHA256, which is the only
                // supported hash currently.
                let msg_hash = sha256(msg);
                ecdsa_secp256k1::verify(signature, &msg_hash, &public_key)
            }
            (
                AlgorithmId::Ed25519,
                CspSignature::Ed25519(signature),
                CspPublicKey::Ed25519(public_key),
            ) =>
            // Ed25519 CLib impl. hashes the message,
            // as the hash algorithm is fixed, so we pass the full message.
            {
                ed25519::verify(signature, msg, &public_key)
            }
            (
                AlgorithmId::RsaSha256,
                CspSignature::RsaSha256(signature),
                CspPublicKey::RsaSha256(public_key),
            ) =>
            // RSA hashes the message using SHA-256
            {
                public_key.verify_pkcs1_sha256(msg, signature)
            }
            (
                AlgorithmId::MultiBls12_381,
                CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(signature)),
                CspPublicKey::MultiBls12_381(public_key),
            ) => multi_sig::verify_individual(msg, *signature, public_key),
            (.., signer) => Err(CryptoError::SignatureVerification {
                algorithm: algorithm_id,
                public_key_bytes: signer.as_ref().to_vec(),
                sig_bytes: sig.as_ref().to_vec(),
                internal_error: "Unsupported types".to_string(),
            }),
        }
    }

    fn verify_pop(
        &self,
        pop: &CspPop,
        algorithm_id: AlgorithmId,
        public_key: CspPublicKey,
    ) -> CryptoResult<()> {
        match (algorithm_id, *pop, public_key) {
            (
                AlgorithmId::MultiBls12_381,
                CspPop::MultiBls12_381(pop),
                CspPublicKey::MultiBls12_381(public_key_bytes),
            ) => multi_sig::verify_pop(pop, public_key_bytes),
            (.., pop, public_key) => Err(CryptoError::PopVerification {
                algorithm: algorithm_id,
                public_key_bytes: public_key.as_ref().to_vec(),
                pop_bytes: pop.as_ref().to_vec(),
                internal_error: "Unsupported types".to_string(),
            }),
        }
    }

    fn combine_sigs(
        &self,
        signatures: Vec<(CspPublicKey, CspSignature)>,
        algorithm_id: AlgorithmId,
    ) -> CryptoResult<CspSignature> {
        match algorithm_id {
            AlgorithmId::MultiBls12_381 => {
                let signatures: CryptoResult<Vec<multi_sig::types::IndividualSignatureBytes>> =
                    signatures
                        .iter()
                        .map(|(_public_key, signature)| match signature {
                            CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(
                                signature,
                            )) => Ok(*signature),
                            _ => Err(CryptoError::AlgorithmNotSupported {
                                algorithm: signature.algorithm(),
                                reason: "Not a multi-signature algorithm".to_string(),
                            }),
                        })
                        .collect();
                Ok(CspSignature::MultiBls12_381(
                    MultiBls12_381_Signature::Combined(multi_sig::combine(&signatures?[..])?),
                ))
            }
            _ => Err(CryptoError::AlgorithmNotSupported {
                algorithm: algorithm_id,
                reason: "Not a multi-signature algorithm".to_string(),
            }),
        }
    }

    fn verify_multisig(
        &self,
        signers: Vec<CspPublicKey>,
        signature: CspSignature,
        msg: &[u8],
        algorithm_id: AlgorithmId,
    ) -> CryptoResult<()> {
        match (algorithm_id, signature) {
            (
                AlgorithmId::MultiBls12_381,
                CspSignature::MultiBls12_381(MultiBls12_381_Signature::Combined(signature)),
            ) => {
                let signers: CryptoResult<Vec<multi_sig::types::PublicKeyBytes>> = signers
                    .iter()
                    .map(|signer| match signer {
                        CspPublicKey::MultiBls12_381(signer) => Ok(*signer),
                        _ => Err(CryptoError::SignatureVerification {
                            algorithm: algorithm_id,
                            public_key_bytes: signer.as_ref().to_vec(),
                            sig_bytes: signature.0.to_vec(),
                            internal_error: "Public key not of type MultiBls12_381".to_string(),
                        }),
                    })
                    .collect();
                multi_sig::verify_combined(msg, signature, &signers?[..])
            }
            _ => Err(CryptoError::AlgorithmNotSupported {
                algorithm: algorithm_id,
                reason: "Not a multi-signature algorithm".to_string(),
            }),
        }
    }
}
