//! Utilities for key generation and key identifier generation

use crate::api::{CspKeyGenerator, CspSecretKeyStoreChecker};
use crate::key_id::KeyId;
use crate::secret_key_store::panic_due_to_duplicated_key_id;
use crate::types::{CspPop, CspPublicKey};
use crate::vault::api::CspTlsKeygenError;
use crate::Csp;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::{AlgorithmId, CryptoError};
use ic_types::NodeId;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

impl CspKeyGenerator for Csp {
    fn gen_key_pair(&self, alg_id: AlgorithmId) -> Result<CspPublicKey, CryptoError> {
        match alg_id {
            AlgorithmId::MultiBls12_381 => {
                let (csp_pk, _pop) = self.csp_vault.gen_key_pair_with_pop(alg_id)?;
                Ok(csp_pk)
            }
            _ => {
                let csp_pk = self.csp_vault.gen_key_pair(alg_id)?;
                Ok(csp_pk)
            }
        }
    }
    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(CspPublicKey, CspPop), CryptoError> {
        let (csp_pk, pop) = self.csp_vault.gen_key_pair_with_pop(algorithm_id)?;
        Ok((csp_pk, pop))
    }

    fn gen_tls_key_pair(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<TlsPublicKeyCert, CryptoError> {
        let cert = self
            .csp_vault
            .gen_tls_key_pair(node, not_after)
            .map_err(|e| match e {
                CspTlsKeygenError::InvalidNotAfterDate {
                    message: msg,
                    not_after: date,
                } => CryptoError::InvalidNotAfterDate {
                    message: msg,
                    not_after: date,
                },
                CspTlsKeygenError::InternalError {
                    internal_error: msg,
                } => CryptoError::InternalError {
                    internal_error: msg,
                },
                CspTlsKeygenError::DuplicateKeyId { key_id } => {
                    panic_due_to_duplicated_key_id(key_id)
                }
            })?;
        Ok(cert)
    }
}

impl CspSecretKeyStoreChecker for Csp {
    fn sks_contains(&self, key_id: &KeyId) -> Result<bool, CryptoError> {
        Ok(self.csp_vault.sks_contains(key_id)?)
    }

    fn sks_contains_tls_key(&self, cert: &TlsPublicKeyCert) -> Result<bool, CryptoError> {
        // we calculate the key_id first to minimize locking time:
        let key_id = KeyId::from(cert);
        self.sks_contains(&key_id)
    }
}

/// Some key related utils
pub mod utils {
    use ic_crypto_internal_types::encrypt::forward_secure::{
        CspFsEncryptionPop, CspFsEncryptionPublicKey,
    };
    use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
    use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;

    /// Form a protobuf structure of the public key and proof of possession
    pub fn dkg_dealing_encryption_pk_to_proto(
        pk: CspFsEncryptionPublicKey,
        pop: CspFsEncryptionPop,
    ) -> PublicKeyProto {
        match (pk, pop) {
            (
                CspFsEncryptionPublicKey::Groth20_Bls12_381(fs_enc_pk),
                CspFsEncryptionPop::Groth20WithPop_Bls12_381(_),
            ) => PublicKeyProto {
                algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
                key_value: fs_enc_pk.as_bytes().to_vec(),
                version: 0,
                proof_data: Some(serde_cbor::to_vec(&pop).expect(
                    "Failed to serialize DKG dealing encryption key proof of possession (PoP) to CBOR",
                )),
            },
            _=> panic!("Unsupported types")
        }
    }
}
