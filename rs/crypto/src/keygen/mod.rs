#[cfg(test)]
mod tests;

use crate::sign::{
    fetch_idkg_dealing_encryption_public_key_from_registry, MegaKeyFromRegistryError,
};
use crate::{key_from_registry, CryptoComponentFatClient};
use ic_crypto_internal_csp::api::CspSecretKeyStoreChecker;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::keygen::utils::idkg_dealing_encryption_pk_to_proto;
use ic_crypto_internal_csp::types::conversions::CspPopFromPublicKeyProtoError;
use ic_crypto_internal_csp::types::{CspPop, CspPublicKey};
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_logmon::metrics::KeyCounts;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_node_key_generation::{mega_public_key_from_proto, MEGaPublicKeyFromProtoError};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_interfaces::crypto::{
    IDkgDealingEncryptionKeyRotationError, KeyManager, PublicKeyRegistrationStatus,
};
use ic_logger::{error, info};
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult, CurrentNodePublicKeys, KeyPurpose};
use ic_types::{RegistryVersion, Time};
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;

impl<C: CryptoServiceProvider> KeyManager for CryptoComponentFatClient<C> {
    fn check_keys_with_registry(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<PublicKeyRegistrationStatus> {
        self.collect_and_store_key_count_metrics(registry_version);
        // Get the public keys from the registry, and ensure that we have the
        // secret keys locally in the SKS.
        let node_signing_key = self.ensure_node_signing_key_material_is_set_up(registry_version)?;
        let committee_signing_key =
            self.ensure_committee_signing_key_material_is_set_up(registry_version)?;
        let dkg_dealing_encryption_key =
            self.ensure_dkg_dealing_encryption_key_material_is_set_up(registry_version)?;
        let tls_certificate = self.ensure_tls_key_material_is_set_up(registry_version)?;
        let idkg_dealing_encryption_key =
            self.ensure_idkg_dealing_encryption_key_material_is_set_up(registry_version)?;

        // Make sure that for each public key found in the registry, we also have the public key
        // locally in the public key store.
        let keys_in_registry = CurrentNodePublicKeys {
            node_signing_public_key: Some(node_signing_key),
            committee_signing_public_key: Some(committee_signing_key),
            tls_certificate: Some(tls_certificate),
            dkg_dealing_encryption_public_key: Some(dkg_dealing_encryption_key),
            idkg_dealing_encryption_public_key: Some(idkg_dealing_encryption_key.clone()),
        };

        if !self.csp.pks_contains(keys_in_registry)? {
            // This may be due to a malicious entity registering new key(s) for this node.
            // Some more drastic action should be taken here; at the moment, we just log and
            // return an error.
            error!(
                self.logger,
                "One or more node keys from the registry are missing locally"
            );
            return Err(CryptoError::PublicKeyNotFound {
                node_id: self.node_id,
                key_purpose: KeyPurpose::Placeholder,
                registry_version,
            });
        }

        // Check if the latest iDKG key we have locally still needs to be registered in the
        // registry, or if it needs to be rotated.
        if let Some(latest_local_idkg_dealing_encryption_key) = self
            .current_node_public_keys()
            .idkg_dealing_encryption_public_key
        {
            if idkg_dealing_encryption_key
                .equal_ignoring_timestamp(&latest_local_idkg_dealing_encryption_key)
            {
                match idkg_dealing_encryption_key.timestamp {
                    None => {
                        // The key in the registry has no timestamp, so it shall be rotated
                        info!(
                            self.logger,
                            "iDKG dealing encryption key has no timestamp and needs rotating"
                        );
                        //////////////////////////////////////////////////////////////////
                        // TODO: When key rotation is to be enabled as part of CRP-1787, change the
                        //  return value to be the one commented out below, instead of
                        //  Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
                        //////////////////////////////////////////////////////////////////
                        // return Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys);
                        //////////////////////////////////////////////////////////////////
                        return Ok(PublicKeyRegistrationStatus::AllKeysRegistered);
                    }
                    Some(timestamp_in_millis) => {
                        if self.is_current_key_too_old(timestamp_in_millis) {
                            info!(
                                self.logger,
                                "iDKG dealing encryption key too old and needs rotating"
                            );
                            //////////////////////////////////////////////////////////////////
                            // TODO: When key rotation is to be enabled as part of CRP-1787, change the
                            //  return value to be the one commented out below, instead of
                            //  Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
                            //////////////////////////////////////////////////////////////////
                            // return Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys);
                            //////////////////////////////////////////////////////////////////
                            return Ok(PublicKeyRegistrationStatus::AllKeysRegistered);
                        }
                    }
                }
            } else {
                info!(
                    self.logger,
                    "Local iDKG dealing encryption key needs registration"
                );
                //////////////////////////////////////////////////////////////////
                // TODO: When key rotation is to be enabled as part of CRP-1787, change the
                //  return value to be the one commented out below, instead of
                //  Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
                //////////////////////////////////////////////////////////////////
                // return Ok(
                //     PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(
                //         latest_local_idkg_dealing_encryption_key,
                //     ),
                // );
                //////////////////////////////////////////////////////////////////
                return Ok(PublicKeyRegistrationStatus::AllKeysRegistered);
            }
        } else {
            panic!("No iDKG dealing encryption key found locally");
        }
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    }

    fn collect_and_store_key_count_metrics(&self, registry_version: RegistryVersion) {
        self.metrics
            .observe_node_key_counts(self.collect_key_count_metrics(registry_version));
    }

    fn current_node_public_keys(&self) -> CurrentNodePublicKeys {
        self.csp.current_node_public_keys()
    }

    fn rotate_idkg_dealing_encryption_keys(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<PublicKeyProto, IDkgDealingEncryptionKeyRotationError> {
        let current_idkg_public_key_proto = (&self.current_node_public_keys().idkg_dealing_encryption_public_key
            .expect("missing local IDKG public key! \
            This should not happen because it's expected that check_keys_with_registry() was called before \
            to ensure that rotation was needed.")).clone();
        let idkg_public_key_from_registry = fetch_idkg_dealing_encryption_public_key_from_registry(
            &self.node_id,
            &self.registry_client,
            registry_version,
        );
        match idkg_public_key_from_registry {
            Ok(registry_idkg_public_key_proto) => {
                if !registry_idkg_public_key_proto
                    .equal_ignoring_timestamp(&current_idkg_public_key_proto)
                {
                    return Ok(current_idkg_public_key_proto);
                }
                match registry_idkg_public_key_proto.timestamp {
                    None => Ok(idkg_dealing_encryption_pk_to_proto(
                        self.csp.idkg_gen_dealing_encryption_key_pair()?,
                    )),
                    Some(timestamp_in_millis) => {
                        if self.is_current_key_too_old(timestamp_in_millis) {
                            Ok(idkg_dealing_encryption_pk_to_proto(
                                self.csp.idkg_gen_dealing_encryption_key_pair()?,
                            ))
                        } else {
                            Err(IDkgDealingEncryptionKeyRotationError::LatestLocalRotationTooRecent)
                        }
                    }
                }
            }
            Err(MegaKeyFromRegistryError::RegistryError(client_error)) => Err(
                IDkgDealingEncryptionKeyRotationError::RegistryError(client_error),
            ),
            Err(error @ MegaKeyFromRegistryError::PublicKeyNotFound { .. }) => {
                error!(
                    self.logger,
                    "IDKG dealing encryption public key not found in registry {:?}", error
                );
                Ok(current_idkg_public_key_proto)
            }
            Err(error @ MegaKeyFromRegistryError::UnsupportedAlgorithm { .. }) => {
                error!(
                    self.logger,
                    "IDKG dealing encryption public key from registry uses an unsupported algorithm {:?}", error
                );
                Ok(current_idkg_public_key_proto)
            }

            Err(error @ MegaKeyFromRegistryError::MalformedPublicKey { .. }) => {
                error!(
                    self.logger,
                    "IDKG dealing encryption public key from registry is malformed {:?}", error
                );
                Ok(current_idkg_public_key_proto)
            }
        }
    }
}

// Helpers for implementing `KeyManager`-trait.
impl<C: CryptoServiceProvider> CryptoComponentFatClient<C> {
    pub fn collect_key_count_metrics(&self, registry_version: RegistryVersion) -> KeyCounts {
        let mut pub_keys_in_reg: u8 = 0;
        let mut secret_keys_in_sks: u8 = 0;
        let pub_keys_local = self
            .current_node_public_keys()
            .get_pub_keys_and_cert_count();
        let reg_and_secret_key_results = vec![
            self.ensure_node_signing_key_material_is_set_up(registry_version)
                .map(|_| ()),
            self.ensure_committee_signing_key_material_is_set_up(registry_version)
                .map(|_| ()),
            self.ensure_dkg_dealing_encryption_key_material_is_set_up(registry_version)
                .map(|_| ()),
            self.ensure_idkg_dealing_encryption_key_material_is_set_up(registry_version)
                .map(|_| ()),
            self.ensure_tls_key_material_is_set_up(registry_version)
                .map(|_| ()),
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
    ) -> CryptoResult<PublicKeyProto> {
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
        ensure_node_signing_key_material_is_set_up_correctly(pk_proto.clone(), &self.csp)?;
        Ok(pk_proto)
    }

    fn ensure_committee_signing_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<PublicKeyProto> {
        let pk_proto = key_from_registry(
            Arc::clone(&self.registry_client),
            self.node_id,
            KeyPurpose::CommitteeSigning,
            registry_version,
        )?;
        ensure_committee_signing_key_material_is_set_up_correctly(pk_proto.clone(), &self.csp)?;
        Ok(pk_proto)
    }

    fn ensure_dkg_dealing_encryption_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<PublicKeyProto> {
        let pk_proto = key_from_registry(
            Arc::clone(&self.registry_client),
            self.node_id,
            KeyPurpose::DkgDealingEncryption,
            registry_version,
        )?;
        ensure_dkg_dealing_encryption_key_material_is_set_up_correctly(
            pk_proto.clone(),
            &self.csp,
        )?;
        Ok(pk_proto)
    }

    fn ensure_idkg_dealing_encryption_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<PublicKeyProto> {
        let pk_proto = key_from_registry(
            Arc::clone(&self.registry_client),
            self.node_id,
            KeyPurpose::IDkgMEGaEncryption,
            registry_version,
        )?;
        ensure_idkg_dealing_encryption_key_material_is_set_up_correctly(
            pk_proto.clone(),
            &self.csp,
        )?;
        Ok(pk_proto)
    }

    fn ensure_tls_key_material_is_set_up(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<X509PublicKeyCert> {
        let public_key_cert = self
            .registry_client
            .get_tls_certificate(self.node_id, registry_version)?
            .ok_or(CryptoError::TlsCertNotFound {
                node_id: self.node_id,
                registry_version,
            })?;
        ensure_tls_key_material_is_set_up_correctly(public_key_cert.clone(), &self.csp)?;
        Ok(public_key_cert)
    }

    fn is_current_key_too_old(&self, timestamp_in_millis: u64) -> bool {
        //TODO CRP-1727: get delta value from registry
        let two_weeks = Duration::from_secs(2 * 7 * 24 * 60 * 60);
        let time_of_registration = Time::from_nanos_since_unix_epoch(
            timestamp_in_millis
                .checked_mul(1_000_000)
                .expect("should not happen before around 580 years"),
        );
        let current_time = self.time_source.get_relative_time();
        current_time > time_of_registration + two_weeks
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
