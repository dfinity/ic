#[cfg(test)]
mod tests;

use crate::tls::{tls_cert_from_registry_raw, TlsCertFromRegistryError};
use crate::{key_from_registry, CryptoComponentImpl};
use ic_crypto_internal_csp::keygen::utils::idkg_dealing_encryption_pk_to_proto;
use ic_crypto_internal_csp::types::ExternalPublicKeys;
use ic_crypto_internal_csp::vault::api::{
    CspPublicKeyStoreError, NodeKeysErrors, PksAndSksContainsErrors,
};
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_logmon::metrics::{
    BooleanOperation, BooleanResult, KeyCounts, KeyRotationResult, MetricsResult,
};
use ic_interfaces::crypto::{
    CheckKeysWithRegistryError, CurrentNodePublicKeysError, IDkgDealingEncryptionKeyRotationError,
    IDkgKeyRotationResult, KeyManager, KeyRotationOutcome,
};
use ic_logger::{error, info, warn};
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::crypto::{CryptoError, CryptoResult, CurrentNodePublicKeys, KeyPurpose};
use ic_types::registry::RegistryClientError;
use ic_types::{RegistryVersion, Time};
use std::time::Duration;

impl<C: CryptoServiceProvider> KeyManager for CryptoComponentImpl<C> {
    fn check_keys_with_registry(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<(), CheckKeysWithRegistryError> {
        // Get the current public keys from the registry, and the number of keys
        let registry_public_keys_result = self.retrieve_keys_from_registry(registry_version);
        let registry_public_keys_count = registry_public_keys_result.get_key_count();
        let registry_public_keys =
            CryptoResult::<ExternalPublicKeys>::from(registry_public_keys_result);

        match registry_public_keys {
            Ok(registry_public_keys) => {
                // If retrieval of public keys from the registry was successful, check to make sure
                // we have the public keys, and the corresponding secret keys locally
                let pks_and_sks_contains_result =
                    self.vault.pks_and_sks_contains(registry_public_keys);
                match pks_and_sks_contains_result {
                    Ok(()) => {
                        self.observe_all_key_counts(
                            &KeyCounts::new(
                                PUBLIC_KEY_TYPE_COUNT,
                                PUBLIC_KEY_TYPE_COUNT,
                                PUBLIC_KEY_TYPE_COUNT,
                            ),
                            MetricsResult::Ok,
                        );
                        Ok(())
                    }

                    Err(PksAndSksContainsErrors::NodeKeysErrors(node_keys_errors)) => {
                        warn!(
                            self.logger,
                            "error while checking keys with registry: {:?}", node_keys_errors
                        );
                        // Explicitly make metrics observation of keys found in the registry, but not
                        // locally - if this occurs, it will trigger a FIT alert
                        self.observe_keys_in_registry_but_missing_locally(&node_keys_errors);
                        self.observe_all_key_counts(
                            &KeyCounts::from(&node_keys_errors),
                            MetricsResult::Ok,
                        );
                        Err(CryptoError::InternalError {
                            internal_error: format!(
                                "Error calling pks_and_sks_contains: {:?}",
                                node_keys_errors
                            ),
                        })
                    }

                    Err(PksAndSksContainsErrors::TransientInternalError(internal_error)) => {
                        self.observe_all_key_counts(&KeyCounts::ZERO, MetricsResult::Err);
                        Err(CryptoError::TransientInternalError {
                            internal_error: format!(
                                "Transient error calling pks_and_sks_contains: {:?}",
                                internal_error
                            ),
                        })
                    }
                }?;
                Ok(())
            }
            Err(err) => {
                // One or more node keys were missing from the registry - make a metrics observation
                // and return the first error encountered
                self.metrics.observe_node_key_counts(
                    &KeyCounts::new(registry_public_keys_count, 0, 0),
                    MetricsResult::Err,
                );
                Err(CheckKeysWithRegistryError::from(err))
            }
        }
    }

    fn current_node_public_keys(
        &self,
    ) -> Result<CurrentNodePublicKeys, CurrentNodePublicKeysError> {
        let result = self.vault.current_node_public_keys()?;
        Ok(result)
    }

    fn rotate_idkg_dealing_encryption_keys(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError> {
        let key_rotation_result =
            self.rotate_idkg_dealing_encryption_keys_internal(registry_version);
        self.record_key_rotation_metrics(&key_rotation_result);
        key_rotation_result
    }
}

// Helpers for implementing `KeyManager`-trait.
impl<C: CryptoServiceProvider> CryptoComponentImpl<C> {
    fn retrieve_keys_from_registry(&self, registry_version: RegistryVersion) -> RegistryKeysResult {
        let node_signing_public_key = key_from_registry(
            self.registry_client.as_ref(),
            self.node_id,
            KeyPurpose::NodeSigning,
            registry_version,
        );
        let committee_signing_public_key = key_from_registry(
            self.registry_client.as_ref(),
            self.node_id,
            KeyPurpose::CommitteeSigning,
            registry_version,
        );
        let tls_certificate = tls_cert_from_registry_raw(
            self.registry_client.as_ref(),
            self.node_id,
            registry_version,
        )
        .map_err(to_crypto_error);
        let dkg_dealing_encryption_public_key = key_from_registry(
            self.registry_client.as_ref(),
            self.node_id,
            KeyPurpose::DkgDealingEncryption,
            registry_version,
        );
        let idkg_dealing_encryption_public_key = key_from_registry(
            self.registry_client.as_ref(),
            self.node_id,
            KeyPurpose::IDkgMEGaEncryption,
            registry_version,
        );
        RegistryKeysResult {
            node_signing_key_result: node_signing_public_key,
            committee_signing_key_result: committee_signing_public_key,
            tls_certificate_result: tls_certificate,
            dkg_dealing_encryption_key_result: dkg_dealing_encryption_public_key,
            idkg_dealing_encryption_key_result: idkg_dealing_encryption_public_key,
        }
    }

    fn rotate_idkg_dealing_encryption_keys_internal(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError> {
        let key_rotation_period: Duration = if let Some(key_rotation_period) =
            self.get_rotation_period_for_current_node_if_key_rotation_enabled(registry_version)?
        {
            key_rotation_period
        } else {
            info!(
                self.logger,
                "iDKG dealing encryption key rotation not enabled"
            );
            return Err(IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled);
        };

        let (current_idkg_public_key_proto, latest_local_idkg_dealing_encryption_key_timestamp) =
            self.current_idkg_dealing_encryption_public_key_and_timestamp()?;
        let idkg_public_key_from_registry = self.registry_client.get_crypto_key_for_node(
            self.node_id,
            KeyPurpose::IDkgMEGaEncryption,
            registry_version,
        )?;
        match idkg_public_key_from_registry {
            None => {
                error!(
                    self.logger,
                    "IDKG dealing encryption public key not found in registry",
                );
                Err(IDkgDealingEncryptionKeyRotationError::RegistryKeyBadOrMissing)
            }
            Some(registry_idkg_public_key_proto) => {
                if !registry_idkg_public_key_proto
                    .equal_ignoring_timestamp(&current_idkg_public_key_proto)
                {
                    info!(
                        self.logger,
                        "Local iDKG dealing encryption key needs registration"
                    );
                    if let Some(latest_local_idkg_dealing_encryption_key_timestamp) =
                        latest_local_idkg_dealing_encryption_key_timestamp
                    {
                        if self.is_current_key_too_old(
                            latest_local_idkg_dealing_encryption_key_timestamp,
                            key_rotation_period,
                        ) {
                            warn!(
                                self.logger,
                                "Local iDKG dealing encryption key is too old ({}), but it still has not been registered in the registry",
                                latest_local_idkg_dealing_encryption_key_timestamp;
                            );
                            return Ok(
                                IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(
                                    KeyRotationOutcome::KeyNotRotatedButTooOld {
                                        existing_key: current_idkg_public_key_proto,
                                    },
                                ),
                            );
                        }
                    }
                    return Ok(
                        IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(
                            KeyRotationOutcome::KeyNotRotated {
                                existing_key: current_idkg_public_key_proto,
                            },
                        ),
                    );
                }
                match get_key_timestamp(&registry_idkg_public_key_proto) {
                    None => {
                        // The key in the registry has no timestamp, so it shall be rotated
                        info!(
                            self.logger,
                            "iDKG dealing encryption key has no timestamp and needs rotating"
                        );
                        Ok(
                            IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(
                                KeyRotationOutcome::KeyRotated {
                                    new_key: idkg_dealing_encryption_pk_to_proto(
                                        self.vault.idkg_gen_dealing_encryption_key_pair()?,
                                    ),
                                },
                            ),
                        )
                    }
                    Some(timestamp_in_millis) => {
                        if self.is_current_key_too_old(timestamp_in_millis, key_rotation_period) {
                            info!(
                                self.logger,
                                "iDKG dealing encryption key too old and needs rotating"
                            );
                            Ok(
                                IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(
                                    KeyRotationOutcome::KeyRotated {
                                        new_key: idkg_dealing_encryption_pk_to_proto(
                                            self.vault.idkg_gen_dealing_encryption_key_pair()?,
                                        ),
                                    },
                                ),
                            )
                        } else {
                            Ok(IDkgKeyRotationResult::LatestRotationTooRecent)
                        }
                    }
                }
            }
        }
    }

    fn record_key_rotation_metrics(
        &self,
        key_rotation_result: &Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError>,
    ) {
        match key_rotation_result {
            Ok(result) => match result {
                IDkgKeyRotationResult::LatestRotationTooRecent => {
                    self.metrics.observe_key_rotation_result(
                        KeyRotationResult::LatestLocalRotationTooRecent,
                    );
                    self.metrics.observe_boolean_result(
                        BooleanOperation::LatestLocalIdkgKeyExistsInRegistry,
                        BooleanResult::True,
                    );
                }
                IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(outcome) => {
                    match outcome {
                        KeyRotationOutcome::KeyRotated { .. } => {
                            self.metrics
                                .observe_key_rotation_result(KeyRotationResult::KeyRotated);
                            self.metrics.observe_boolean_result(
                                BooleanOperation::LatestLocalIdkgKeyExistsInRegistry,
                                BooleanResult::True,
                            );
                        }
                        KeyRotationOutcome::KeyNotRotated { .. } => {
                            self.metrics
                                .observe_key_rotation_result(KeyRotationResult::KeyNotRotated);
                            self.metrics.observe_boolean_result(
                                BooleanOperation::LatestLocalIdkgKeyExistsInRegistry,
                                BooleanResult::False,
                            );
                        }
                        KeyRotationOutcome::KeyNotRotatedButTooOld { .. } => {
                            self.metrics
                                    .observe_latest_idkg_dealing_encryption_public_key_too_old_but_not_in_registry(
                                    );
                        }
                    }
                }
            },
            Err(err) => match err {
                IDkgDealingEncryptionKeyRotationError::KeyGenerationError(_) => {
                    self.metrics
                        .observe_key_rotation_result(KeyRotationResult::KeyGenerationError);
                }
                IDkgDealingEncryptionKeyRotationError::RegistryClientError(_) => {
                    self.metrics
                        .observe_key_rotation_result(KeyRotationResult::RegistryError);
                }
                IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled => {
                    self.metrics
                        .observe_key_rotation_result(KeyRotationResult::KeyRotationNotEnabled);
                }
                IDkgDealingEncryptionKeyRotationError::TransientInternalError(_) => {
                    self.metrics
                        .observe_key_rotation_result(KeyRotationResult::TransientInternalError);
                }
                IDkgDealingEncryptionKeyRotationError::PublicKeyNotFound => {
                    self.metrics
                        .observe_key_rotation_result(KeyRotationResult::PublicKeyNotFound);
                }
                IDkgDealingEncryptionKeyRotationError::RegistryKeyBadOrMissing => {
                    self.metrics
                        .observe_key_rotation_result(KeyRotationResult::RegistryKeyBadOrMissing);
                }
            },
        }
    }

    fn current_idkg_dealing_encryption_public_key_and_timestamp(
        &self,
    ) -> Result<(PublicKeyProto, Option<Time>), IDkgDealingEncryptionKeyRotationError> {
        let current_idkg_public_key_proto = self
            .vault
            .current_node_public_keys()
            .map_err(
                |CspPublicKeyStoreError::TransientInternalError(internal_error)| {
                    IDkgDealingEncryptionKeyRotationError::TransientInternalError(internal_error)
                },
            )?
            .idkg_dealing_encryption_public_key
            .ok_or(IDkgDealingEncryptionKeyRotationError::PublicKeyNotFound)?;
        let current_idkg_public_key_proto_with_timestamp = self
            .vault
            .current_node_public_keys_with_timestamps()
            .map_err(
                |CspPublicKeyStoreError::TransientInternalError(internal_error)| {
                    IDkgDealingEncryptionKeyRotationError::TransientInternalError(internal_error)
                },
            )?
            .idkg_dealing_encryption_public_key
            .ok_or(IDkgDealingEncryptionKeyRotationError::PublicKeyNotFound)?;
        if current_idkg_public_key_proto
            .equal_ignoring_timestamp(&current_idkg_public_key_proto_with_timestamp)
        {
            Ok((
                current_idkg_public_key_proto,
                get_key_timestamp(&current_idkg_public_key_proto_with_timestamp),
            ))
        } else {
            warn!(
                self.logger,
                "Race condition: current_node_public_keys() and current_node_public_keys_with_timestamps() returned different iDKG dealing encryption public keys"
            );
            Err(IDkgDealingEncryptionKeyRotationError::TransientInternalError(
                "Race condition: current_node_public_keys() and current_node_public_keys_with_timestamps() returned different iDKG dealing encryption public keys".to_string()))
        }
    }

    fn get_rotation_period_for_current_node_if_key_rotation_enabled(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<Option<Duration>, RegistryClientError> {
        match self
            .registry_client
            .get_listed_subnet_for_node_id(self.node_id, registry_version)?
        {
            None => Ok(None),
            Some((subnet_id, _subnet_record)) => {
                let key_rotation_period = match self
                    .registry_client
                    .get_chain_key_config(subnet_id, registry_version)
                {
                    Ok(Some(config)) if !config.key_configs.is_empty() => {
                        match config.idkg_key_rotation_period_ms {
                            Some(ms) => Duration::from_millis(ms),
                            None => return Ok(None),
                        }
                    }
                    _ => {
                        return Ok(None);
                    }
                };
                Ok(Some(key_rotation_period))
            }
        }
    }

    fn is_current_key_too_old(
        &self,
        time_of_registration: Time,
        key_rotation_period: Duration,
    ) -> bool {
        if let Some(time_to_rotate) = time_of_registration.checked_add(key_rotation_period) {
            let current_time = self.time_source.get_relative_time();
            current_time > time_to_rotate
        } else {
            warn!(
                self.logger,
                "The addition of the key's registration time ({}) \
            with the key rotation period ({:?}) would overflow a u64 of nanoseconds (year 2554). \
            Is the key rotation period misconfigured?",
                time_of_registration,
                key_rotation_period
            );
            // time_of_registration + key_rotation_period overflows so it is guaranteed
            // to be larger than current_time
            false
        }
    }

    fn observe_all_key_counts(&self, key_counts: &KeyCounts, metric_result: MetricsResult) {
        self.metrics
            .observe_node_key_counts(key_counts, metric_result);
        self.observe_number_of_idkg_dealing_encryption_public_keys();
    }

    fn observe_keys_in_registry_but_missing_locally(&self, node_keys_errors: &NodeKeysErrors) {
        if node_keys_errors.keys_in_registry_missing_locally() {
            error!(
                self.logger,
                "One or more node keys from the registry are missing locally ({:?})",
                node_keys_errors
            );
            self.metrics.observe_keys_in_registry_missing_locally();
        }
    }

    fn observe_number_of_idkg_dealing_encryption_public_keys(&self) {
        match self.vault.idkg_dealing_encryption_pubkeys_count() {
            Ok(num_idkg_dealing_encryption_pubkeys) => {
                self.metrics.observe_idkg_dealing_encryption_pubkey_count(
                    num_idkg_dealing_encryption_pubkeys,
                    MetricsResult::Ok,
                );
            }
            Err(CspPublicKeyStoreError::TransientInternalError(internal_error)) => {
                warn!(
                    self.logger,
                    "Transient error retrieving local iDKG dealing encryption public key count: {}",
                    internal_error
                );
                self.metrics
                    .observe_idkg_dealing_encryption_pubkey_count(0, MetricsResult::Err);
            }
        };
    }
}

struct RegistryKeysResult {
    pub node_signing_key_result: CryptoResult<PublicKeyProto>,
    pub committee_signing_key_result: CryptoResult<PublicKeyProto>,
    pub tls_certificate_result: CryptoResult<X509PublicKeyCert>,
    pub dkg_dealing_encryption_key_result: CryptoResult<PublicKeyProto>,
    pub idkg_dealing_encryption_key_result: CryptoResult<PublicKeyProto>,
}

impl From<RegistryKeysResult> for CryptoResult<ExternalPublicKeys> {
    fn from(result: RegistryKeysResult) -> Self {
        Ok(ExternalPublicKeys {
            node_signing_public_key: result.node_signing_key_result?,
            committee_signing_public_key: result.committee_signing_key_result?,
            tls_certificate: result.tls_certificate_result?,
            dkg_dealing_encryption_public_key: result.dkg_dealing_encryption_key_result?,
            idkg_dealing_encryption_public_key: result.idkg_dealing_encryption_key_result?,
        })
    }
}

impl RegistryKeysResult {
    pub fn get_key_count(&self) -> u32 {
        let mut key_count: u32 = 0;
        if self.node_signing_key_result.is_ok() {
            key_count += 1;
        }
        if self.committee_signing_key_result.is_ok() {
            key_count += 1;
        }
        if self.tls_certificate_result.is_ok() {
            key_count += 1;
        }
        if self.dkg_dealing_encryption_key_result.is_ok() {
            key_count += 1;
        }
        if self.idkg_dealing_encryption_key_result.is_ok() {
            key_count += 1;
        }
        key_count
    }
}

fn get_key_timestamp(public_key: &PublicKeyProto) -> Option<Time> {
    public_key.timestamp.map(|timestamp_in_millis| {
        Time::from_millis_since_unix_epoch(timestamp_in_millis)
            .expect("conversion error to happen in the year 2554")
    })
}

fn to_crypto_error(e: TlsCertFromRegistryError) -> CryptoError {
    match e {
        TlsCertFromRegistryError::RegistryError(registry_error) => {
            CryptoError::RegistryClient(registry_error)
        }
        TlsCertFromRegistryError::CertificateNotInRegistry {
            node_id,
            registry_version,
        } => CryptoError::TlsCertNotFound {
            node_id,
            registry_version,
        },
        TlsCertFromRegistryError::CertificateMalformed { internal_error } => {
            CryptoError::InternalError { internal_error }
        }
    }
}

const PUBLIC_KEY_TYPE_COUNT: u32 = 5;
