//! Utilities for key generation and key identifier generation

use crate::api::{CspKeyGenerator, CspSecretKeyStoreChecker};
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreError};
use crate::types::{CspPop, CspPublicKey, CspSecretKey};
use crate::Csp;
use ic_crypto_internal_tls::keygen::generate_tls_key_pair_der;
use ic_crypto_sha::{Context, DomainSeparationContext};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::{AlgorithmId, CryptoError, KeyId};
use ic_types::NodeId;
use openssl::asn1::Asn1Time;
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

const KEY_ID_DOMAIN: &str = "ic-key-id";

use crate::server::api::{
    BasicSignatureCspServer, MultiSignatureCspServer, SecretKeyStoreCspServer,
};
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_crypto_sha::Sha256;
pub use tls_keygen::tls_cert_hash_as_key_id;

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore> CspKeyGenerator for Csp<R, S> {
    fn gen_key_pair(&self, alg_id: AlgorithmId) -> Result<(KeyId, CspPublicKey), CryptoError> {
        match alg_id {
            AlgorithmId::MultiBls12_381 => {
                let (key_id, csp_pk, _pop) = self.csp_server.gen_key_pair_with_pop(alg_id)?;
                Ok((key_id, csp_pk))
            }
            _ => Ok(self.csp_server.gen_key_pair(alg_id)?),
        }
    }
    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CryptoError> {
        Ok(self.csp_server.gen_key_pair_with_pop(algorithm_id)?)
    }

    fn gen_tls_key_pair(&mut self, node: NodeId, not_after: &str) -> TlsPublicKeyCert {
        let serial = self.rng_write_lock().gen::<[u8; 19]>();
        let common_name = &node.get().to_string()[..];
        let not_after = Asn1Time::from_str_x509(not_after)
            .expect("invalid X.509 certificate expiration date (not_after)");
        let (cert, secret_key) = generate_tls_key_pair_der(common_name, serial, &not_after);

        let x509_pk_cert = TlsPublicKeyCert::new_from_der(cert.bytes)
            .expect("generated X509 certificate has malformed DER encoding");
        let _key_id = self.store_tls_secret_key(&x509_pk_cert, secret_key);
        x509_pk_cert
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> CspSecretKeyStoreChecker for Csp<R, S> {
    fn sks_contains(&self, key_id: &KeyId) -> bool {
        self.csp_server.sks_contains(key_id)
    }

    fn sks_contains_tls_key(&self, cert: &TlsPublicKeyCert) -> bool {
        // we calculate the key_id first to minimize locking time:
        let key_id = tls_cert_hash_as_key_id(&cert);
        self.sks_contains(&key_id)
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
    fn store_secret_key_or_panic(&self, csp_secret_key: CspSecretKey, key_id: KeyId) {
        match &self.sks_write_lock().insert(key_id, csp_secret_key, None) {
            Ok(()) => {}
            Err(SecretKeyStoreError::DuplicateKeyId(key_id)) => {
                panic!("A key with ID {} has already been inserted", key_id);
            }
        };
    }
}

/// Compute the key identifier of the given public key
pub fn public_key_hash_as_key_id(pk: &CspPublicKey) -> KeyId {
    bytes_hash_as_key_id(pk.algorithm_id(), pk.pk_bytes())
}

// KeyId is SHA256 computed on the bytes:
//     domain_separator | algorithm_id | size(pk_bytes) | pk_bytes
// where  domain_separator is DomainSeparationContext(KEY_ID_DOMAIN),
// algorithm_id is a 1-byte value, and size(pk_bytes) is the size of
// pk_bytes as u32 in BigEndian format.
fn bytes_hash_as_key_id(alg_id: AlgorithmId, bytes: &[u8]) -> KeyId {
    let mut hash =
        Sha256::new_with_context(&DomainSeparationContext::new(KEY_ID_DOMAIN.to_string()));
    hash.write(&[alg_id as u8]);
    let bytes_size = u32::try_from(bytes.len()).expect("type conversion error");
    hash.write(&bytes_size.to_be_bytes());
    hash.write(bytes);
    KeyId::from(hash.finish())
}

/// Compute the key identifier for a forward secure encryption public key
pub fn forward_secure_key_id(public_key: &CspFsEncryptionPublicKey) -> KeyId {
    let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(
        "KeyId from CspFsEncryptionPublicKey",
    ));
    let variant: &'static str = public_key.into();
    hash.write(DomainSeparationContext::new(variant).as_bytes());
    match public_key {
        CspFsEncryptionPublicKey::Groth20_Bls12_381(public_key) => {
            hash.write(public_key.as_bytes())
        }
    }
    KeyId::from(hash.finish())
}

mod tls_keygen {
    use super::*;
    use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;

    /// Create a key identifier by hashing the bytes of the certificate
    pub fn tls_cert_hash_as_key_id(cert: &TlsPublicKeyCert) -> KeyId {
        bytes_hash_as_key_id(AlgorithmId::Tls, cert.as_der())
    }

    impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
        pub(super) fn store_tls_secret_key(
            &mut self,
            cert: &TlsPublicKeyCert,
            secret_key: TlsEd25519SecretKeyDerBytes,
        ) -> KeyId {
            let key_id = tls_cert_hash_as_key_id(&cert);
            self.store_secret_key_or_panic(CspSecretKey::TlsEd25519(secret_key), key_id);
            key_id
        }
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
