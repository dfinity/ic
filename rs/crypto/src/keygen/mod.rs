use crate::sign::{get_mega_pubkey, MegaKeyFromRegistryError};
use crate::{key_from_registry, CryptoComponentFatClient};
use ic_crypto_internal_csp::keygen::{
    forward_secure_key_id, mega_key_id, public_key_hash_as_key_id,
};
use ic_crypto_internal_csp::types::conversions::CspPopFromPublicKeyProtoError;
use ic_crypto_internal_csp::types::{CspPop, CspPublicKey};
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_interfaces::crypto::{KeyManager, PublicKeyRegistrationStatus};
use ic_logger::warn;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult, KeyPurpose};
use ic_types::RegistryVersion;
use std::convert::TryFrom;
use std::sync::Arc;

impl<C: CryptoServiceProvider> KeyManager for CryptoComponentFatClient<C> {
    fn node_public_keys(&self) -> NodePublicKeys {
        self.csp.node_public_keys()
    }

    fn check_keys_with_registry(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<PublicKeyRegistrationStatus> {
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
}

// Helpers for implementing `KeyManager`-trait.
impl<C: CryptoServiceProvider> CryptoComponentFatClient<C> {
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
        let csp_key = CspPublicKey::try_from(pk_proto)?;
        let key_id = public_key_hash_as_key_id(&csp_key);
        if !self.csp.sks_contains(&key_id) {
            return Err(CryptoError::SecretKeyNotFound {
                algorithm: AlgorithmId::Ed25519,
                key_id,
            });
        }
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
        if AlgorithmId::from(pk_proto.algorithm) != AlgorithmId::MultiBls12_381 {
            return Err(CryptoError::PublicKeyNotFound {
                node_id: self.node_id,
                key_purpose: KeyPurpose::CommitteeSigning,
                registry_version,
            });
        }
        Self::ensure_committe_signing_key_pop_is_well_formed(&pk_proto)?;
        let csp_key = CspPublicKey::try_from(pk_proto)?;
        let key_id = public_key_hash_as_key_id(&csp_key);
        if !self.csp.sks_contains(&key_id) {
            return Err(CryptoError::SecretKeyNotFound {
                algorithm: AlgorithmId::MultiBls12_381,
                key_id,
            });
        }
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
        if AlgorithmId::from(pk_proto.algorithm) != AlgorithmId::Groth20_Bls12_381 {
            return Err(CryptoError::PublicKeyNotFound {
                node_id: self.node_id,
                key_purpose: KeyPurpose::CommitteeSigning,
                registry_version,
            });
        }
        let _csp_pop = CspFsEncryptionPop::try_from(&pk_proto).map_err(|e| {
            CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::Groth20_Bls12_381,
                key_bytes: None,
                internal_error: format!("{:?}", e),
            }
        })?;
        let csp_key = CspFsEncryptionPublicKey::try_from(pk_proto).map_err(|e| {
            CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::Groth20_Bls12_381,
                key_bytes: Some(e.key_bytes),
                internal_error: e.internal_error,
            }
        })?;
        let key_id = forward_secure_key_id(&csp_key);
        if !self.csp.sks_contains(&key_id) {
            return Err(CryptoError::SecretKeyNotFound {
                algorithm: AlgorithmId::Groth20_Bls12_381,
                key_id,
            });
        }
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
        let idkg_dealing_encryption_pk = get_mega_pubkey(
            &self.node_id,
            &self.registry_client,
            registry_version,
        )
        .map_err(|e| match e {
            MegaKeyFromRegistryError::RegistryError(e) => CryptoError::RegistryClient(e),
            MegaKeyFromRegistryError::PublicKeyNotFound { .. } => CryptoError::PublicKeyNotFound {
                node_id: self.node_id,
                key_purpose: KeyPurpose::IDkgMEGaEncryption,
                registry_version,
            },
            MegaKeyFromRegistryError::UnsupportedAlgorithm { algorithm_id } => {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::MegaSecp256k1,
                    key_bytes: None,
                    internal_error: format!(
                        "unsupported algorithm ({:?}) of I-DKG dealing encryption public key of node `{}` in registry",
                        algorithm_id,
                        self.node_id,
                    ),
                }
            }
            MegaKeyFromRegistryError::MalformedPublicKey { node_id, key_bytes } => {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::MegaSecp256k1,
                    key_bytes: Some(key_bytes),
                    internal_error: format!(
                        "I-DKG dealing encryption public key of node `{}` malformed in registry",
                        node_id
                    ),
                }
            }
        })?;

        let key_id = mega_key_id(&idkg_dealing_encryption_pk);
        if !self.csp.sks_contains(&key_id) {
            return Err(CryptoError::SecretKeyNotFound {
                algorithm: AlgorithmId::MegaSecp256k1,
                key_id,
            });
        }
        Ok(())
    }

    fn ensure_tls_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let public_key_cert = self
            .registry_client
            .get_tls_certificate(self.node_id, registry_version)?
            .map_or_else(
                || {
                    Err(CryptoError::TlsCertNotFound {
                        node_id: self.node_id,
                        registry_version,
                    })
                },
                |cert| {
                    TlsPublicKeyCert::new_from_der(cert.certificate_der).map_err(|e| {
                        CryptoError::MalformedPublicKey {
                            algorithm: AlgorithmId::Ed25519,
                            key_bytes: None, // The DER is included in the `internal_error` below.
                            internal_error: format!("{}", e),
                        }
                    })
                },
            )?;

        if !self.csp.sks_contains_tls_key(&public_key_cert) {
            return Err(CryptoError::TlsSecretKeyNotFound {
                certificate_der: public_key_cert.as_der().clone(),
            });
        }

        Ok(())
    }

    fn ensure_committe_signing_key_pop_is_well_formed(
        pk_proto: &PublicKeyProto,
    ) -> CryptoResult<()> {
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
}
