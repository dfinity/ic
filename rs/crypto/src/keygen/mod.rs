#[cfg(test)]
mod tests;

use crate::sign::{get_mega_pubkey, MegaKeyFromRegistryError};
use crate::{key_from_registry, CryptoComponentFatClient};
use ic_crypto_internal_csp::api::CspSecretKeyStoreChecker;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::conversions::CspPopFromPublicKeyProtoError;
use ic_crypto_internal_csp::types::{CspPop, CspPublicKey};
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_logmon::metrics::KeyCounts;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_node_key_generation::{mega_public_key_from_proto, MEGaPublicKeyFromProtoError};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_interfaces::crypto::{KeyManager, PublicKeyRegistrationStatus};
use ic_logger::warn;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult, KeyPurpose};
use ic_types::RegistryVersion;
use std::convert::TryFrom;
use std::sync::Arc;

impl<C: CryptoServiceProvider> KeyManager for CryptoComponentFatClient<C> {
    fn check_keys_with_registry(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<PublicKeyRegistrationStatus> {
        self.collect_and_store_key_count_metrics(registry_version);
        self.ensure_node_signing_key_material_is_set_up(registry_version)?;
        self.ensure_committee_signing_key_material_is_set_up(registry_version)?;
        self.ensure_dkg_dealing_encryption_key_material_is_set_up(registry_version)?;
        self.ensure_tls_key_material_is_set_up(registry_version)?;

        if let Some(pubkey) = self.unregistered_idkg_dealing_encryption_key(registry_version) {
            return Ok(PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(pubkey));
        }
        if self.node_public_keys().idkg_dealing_encryption_pk.is_none() {
            warn!(
                self.logger,
                "iDKG dealing encryption key of node {} is missing in local public key store",
                self.node_id
            );
        } else if let Err(error) =
            self.ensure_idkg_dealing_encryption_key_material_is_set_up(registry_version)
        {
            warn!(
                self.logger,
                "iDKG dealing encryption key of node {} is not properly set up \
                  in the registry for registry version {}: {}",
                self.node_id,
                registry_version,
                error
            );
        }
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    }

    fn collect_and_store_key_count_metrics(&self, registry_version: RegistryVersion) {
        self.metrics
            .observe_node_key_counts(self.collect_key_count_metrics(registry_version));
    }

    fn node_public_keys(&self) -> NodePublicKeys {
        self.csp.node_public_keys()
    }
}

// Helpers for implementing `KeyManager`-trait.
impl<C: CryptoServiceProvider> CryptoComponentFatClient<C> {
    pub fn collect_key_count_metrics(&self, registry_version: RegistryVersion) -> KeyCounts {
        let mut pub_keys_in_reg: u8 = 0;
        let mut secret_keys_in_sks: u8 = 0;
        let pub_keys_local = self.node_public_keys().get_pub_keys_and_cert_count();
        let reg_and_secret_key_results = vec![
            self.ensure_node_signing_key_material_is_set_up(registry_version),
            self.ensure_committee_signing_key_material_is_set_up(registry_version),
            self.ensure_dkg_dealing_encryption_key_material_is_set_up(registry_version),
            self.ensure_idkg_dealing_encryption_key_material_is_set_up(registry_version),
            self.ensure_tls_key_material_is_set_up(registry_version),
        ];
        for r in reg_and_secret_key_results.iter() {
            match r {
                Ok(_) => {
                    pub_keys_in_reg += 1;
                    secret_keys_in_sks += 1;
                }
                Err(CryptoError::SecretKeyNotFound { .. }) => {
                    pub_keys_in_reg += 1;
                }
                Err(CryptoError::TlsSecretKeyNotFound { .. }) => {
                    pub_keys_in_reg += 1;
                }
                _ => {}
            }
        }
        KeyCounts::new(pub_keys_in_reg, pub_keys_local, secret_keys_in_sks)
    }

    fn ensure_node_signing_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let pk_proto = key_from_registry(
            Arc::clone(&self.registry_client),
            self.node_id,
            KeyPurpose::NodeSigning,
            registry_version,
        )?;
        if AlgorithmId::from(pk_proto.algorithm) != AlgorithmId::Ed25519 {
            return Err(CryptoError::PublicKeyNotFound {
                node_id: self.node_id,
                key_purpose: KeyPurpose::NodeSigning,
                registry_version,
            });
        }
        self.compare_local_and_registry_public_keys_and_certificates(
            self.node_public_keys().node_signing_pk.as_ref(),
            &pk_proto,
            registry_version,
            "node signing public key",
        );
        ensure_node_signing_key_material_is_set_up_correctly(pk_proto, &self.csp)?;
        Ok(())
    }

    fn ensure_committee_signing_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let pk_proto = key_from_registry(
            Arc::clone(&self.registry_client),
            self.node_id,
            KeyPurpose::CommitteeSigning,
            registry_version,
        )?;
        self.compare_local_and_registry_public_keys_and_certificates(
            self.node_public_keys().committee_signing_pk.as_ref(),
            &pk_proto,
            registry_version,
            "committee signing public key",
        );
        ensure_committee_signing_key_material_is_set_up_correctly(pk_proto, &self.csp)?;
        Ok(())
    }

    fn ensure_dkg_dealing_encryption_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let pk_proto = key_from_registry(
            Arc::clone(&self.registry_client),
            self.node_id,
            KeyPurpose::DkgDealingEncryption,
            registry_version,
        )?;
        self.compare_local_and_registry_public_keys_and_certificates(
            self.node_public_keys().dkg_dealing_encryption_pk.as_ref(),
            &pk_proto,
            registry_version,
            "NI-DKG dealing encryption key",
        );
        ensure_dkg_dealing_encryption_key_material_is_set_up_correctly(pk_proto, &self.csp)?;
        Ok(())
    }

    fn unregistered_idkg_dealing_encryption_key(
        &self,
        registry_version: RegistryVersion,
    ) -> Option<PublicKeyProto> {
        let result = get_mega_pubkey(&self.node_id, &self.registry_client, registry_version);
        if let Err(MegaKeyFromRegistryError::PublicKeyNotFound { .. }) = result {
            if let Some(idkg_dealing_enc_pk) = self.node_public_keys().idkg_dealing_encryption_pk {
                return Some(idkg_dealing_enc_pk);
            }
        }
        None
    }

    fn ensure_idkg_dealing_encryption_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let pk_proto = key_from_registry(
            Arc::clone(&self.registry_client),
            self.node_id,
            KeyPurpose::IDkgMEGaEncryption,
            registry_version,
        )?;
        self.compare_local_and_registry_public_keys_and_certificates(
            self.node_public_keys().idkg_dealing_encryption_pk.as_ref(),
            &pk_proto,
            registry_version,
            "iDKG dealing encryption key",
        );
        ensure_idkg_dealing_encryption_key_material_is_set_up_correctly(pk_proto, &self.csp)?;
        Ok(())
    }

    fn ensure_tls_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let public_key_cert = self
            .registry_client
            .get_tls_certificate(self.node_id, registry_version)?
            .ok_or(CryptoError::TlsCertNotFound {
                node_id: self.node_id,
                registry_version,
            })?;
        self.compare_local_and_registry_public_keys_and_certificates(
            self.node_public_keys().tls_certificate.as_ref(),
            &public_key_cert,
            registry_version,
            "TLS certificate",
        );
        ensure_tls_key_material_is_set_up_correctly(public_key_cert, &self.csp)?;
        Ok(())
    }

    fn compare_local_and_registry_public_keys_and_certificates<T: PartialEq>(
        &self,
        maybe_local_public_obj: Option<&T>,
        registry_public_obj: &T,
        registry_version: RegistryVersion,
        obj_type: &str,
    ) {
        match maybe_local_public_obj {
            None => warn!(
                self.logger,
                "{} of node {} exists in the registry but not locally \
                    for registry version {}",
                obj_type,
                self.node_id,
                registry_version
            ),
            Some(local_public_obj) => {
                if registry_public_obj != local_public_obj {
                    warn!(
                        self.logger,
                        "{} mismatch between local and registry copies \
                         for node {}, for registry version {}",
                        obj_type,
                        self.node_id,
                        registry_version
                    )
                }
            }
        }
    }
}

pub(crate) fn ensure_node_signing_key_material_is_set_up_correctly(
    pubkey_proto: PublicKeyProto,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    if AlgorithmId::from(pubkey_proto.algorithm) != AlgorithmId::Ed25519 {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: None,
            internal_error: format!(
                "expected public key algorithm Ed25519, but found {:?}",
                AlgorithmId::from(pubkey_proto.algorithm),
            ),
        });
    }
    let csp_key = CspPublicKey::try_from(pubkey_proto)?;
    let key_id = KeyId::from(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::Ed25519,
            key_id: key_id.to_string(),
        });
    }
    Ok(())
}

pub(crate) fn ensure_committee_signing_key_material_is_set_up_correctly(
    pubkey_proto: PublicKeyProto,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    if AlgorithmId::from(pubkey_proto.algorithm) != AlgorithmId::MultiBls12_381 {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::MultiBls12_381,
            key_bytes: None,
            internal_error: format!(
                "expected public key algorithm MultiBls12_381, but found {:?}",
                AlgorithmId::from(pubkey_proto.algorithm),
            ),
        });
    }
    ensure_committe_signing_key_pop_is_well_formed(&pubkey_proto)?;
    let csp_key = CspPublicKey::try_from(pubkey_proto)?;
    let key_id = KeyId::from(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::MultiBls12_381,
            key_id: key_id.to_string(),
        });
    }
    Ok(())
}

fn ensure_committe_signing_key_pop_is_well_formed(pk_proto: &PublicKeyProto) -> CryptoResult<()> {
    CspPop::try_from(pk_proto).map_err(|e| match e {
        CspPopFromPublicKeyProtoError::NoPopForAlgorithm { algorithm } => {
            CryptoError::MalformedPop {
                algorithm,
                pop_bytes: vec![],
                internal_error: format!("{:?}", e),
            }
        }
        CspPopFromPublicKeyProtoError::MissingProofData => CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes: vec![],
            internal_error: format!("{:?}", e),
        },
        CspPopFromPublicKeyProtoError::MalformedPop {
            pop_bytes,
            internal_error,
        } => CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes,
            internal_error,
        },
    })?;

    Ok(())
}

pub(crate) fn ensure_dkg_dealing_encryption_key_material_is_set_up_correctly(
    pubkey_proto: PublicKeyProto,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    if AlgorithmId::from(pubkey_proto.algorithm) != AlgorithmId::Groth20_Bls12_381 {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: None,
            internal_error: format!(
                "expected public key algorithm Groth20_Bls12_381, but found {:?}",
                AlgorithmId::from(pubkey_proto.algorithm),
            ),
        });
    }
    let _csp_pop = CspFsEncryptionPop::try_from(&pubkey_proto).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: None,
            internal_error: format!("{:?}", e),
        }
    })?;
    let csp_key = CspFsEncryptionPublicKey::try_from(pubkey_proto).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: Some(e.key_bytes),
            internal_error: e.internal_error,
        }
    })?;
    let key_id = KeyId::from(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_id: key_id.to_string(),
        });
    }
    Ok(())
}

pub(crate) fn ensure_idkg_dealing_encryption_key_material_is_set_up_correctly(
    pubkey_proto: PublicKeyProto,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    let idkg_dealing_encryption_pk =
        mega_public_key_from_proto(&pubkey_proto).map_err(|e| match e {
            MEGaPublicKeyFromProtoError::UnsupportedAlgorithm { algorithm_id } => {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::MegaSecp256k1,
                    key_bytes: None,
                    internal_error: format!(
                        "unsupported algorithm ({:?}) of I-DKG dealing encryption key",
                        algorithm_id,
                    ),
                }
            }
            MEGaPublicKeyFromProtoError::MalformedPublicKey { key_bytes } => {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::MegaSecp256k1,
                    key_bytes: Some(key_bytes),
                    internal_error: "I-DKG dealing encryption key malformed".to_string(),
                }
            }
        })?;

    let key_id = KeyId::try_from(&idkg_dealing_encryption_pk).map_err(|error| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::MegaSecp256k1,
            key_bytes: Some(idkg_dealing_encryption_pk.serialize()),
            internal_error: format!("failed to derive key ID from MEGa public key: {}", error),
        }
    })?;
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::MegaSecp256k1,
            key_id: key_id.to_string(),
        });
    }
    Ok(())
}

pub(crate) fn ensure_tls_key_material_is_set_up_correctly(
    pubkey_cert_proto: X509PublicKeyCert,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    let public_key_cert = TlsPublicKeyCert::new_from_der(pubkey_cert_proto.certificate_der)
        .map_err(|e| {
            CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::Tls,
                key_bytes: None, // The DER is included in the `internal_error` below.
                internal_error: format!("{}", e),
            }
        })?;

    if !csp.sks_contains_tls_key(&public_key_cert)? {
        return Err(CryptoError::TlsSecretKeyNotFound {
            certificate_der: public_key_cert.as_der().clone(),
        });
    }
    Ok(())
}
