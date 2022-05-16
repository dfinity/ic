use crate::sign::{
    get_mega_pubkey, mega_public_key_from_proto, MEGaPublicKeyFromProtoError,
    MegaKeyFromRegistryError,
};
use crate::{key_from_registry, CryptoComponentFatClient};
use ic_crypto_internal_csp::api::CspSecretKeyStoreChecker;
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
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
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
        ensure_tls_key_material_is_set_up_correctly(public_key_cert, &self.csp)?;
        Ok(())
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
    let key_id = public_key_hash_as_key_id(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::Ed25519,
            key_id,
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
    let key_id = public_key_hash_as_key_id(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::MultiBls12_381,
            key_id,
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
    let key_id = forward_secure_key_id(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_id,
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

    let key_id = mega_key_id(&idkg_dealing_encryption_pk);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::MegaSecp256k1,
            key_id,
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
