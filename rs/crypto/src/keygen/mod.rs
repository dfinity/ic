#[cfg(test)]
mod tests;

use crate::sign::{
    fetch_idkg_dealing_encryption_public_key_from_registry, MegaKeyFromRegistryError,
};
use crate::{key_from_registry, tls_certificate_from_registry, CryptoComponentFatClient};
use ic_crypto_internal_csp::keygen::utils::idkg_dealing_encryption_pk_to_proto;
use ic_crypto_internal_csp::types::ExternalPublicKeys;
use ic_crypto_internal_csp::vault::api::{NodeKeysErrors, PksAndSksContainsErrors};
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_logmon::metrics::{
    BooleanOperation, BooleanResult, KeyCounts, KeyRotationResult, MetricsResult,
};
use ic_interfaces::crypto::{
    CurrentNodePublicKeysError, IDkgDealingEncryptionKeyRotationError,
    IdkgDealingEncPubKeysCountError, KeyManager, PublicKeyRegistrationStatus,
};
use ic_logger::{error, info, warn};
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::crypto::{CryptoError, CryptoResult, CurrentNodePublicKeys, KeyPurpose};
use ic_types::registry::RegistryClientError;
use ic_types::{RegistryVersion, Time};
use std::time::Duration;

impl<C: CryptoServiceProvider> KeyManager for CryptoComponentFatClient<C> {
    fn check_keys_with_registry(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<PublicKeyRegistrationStatus> {
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
                    self.csp.pks_and_sks_contains(registry_public_keys.clone());
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
                // Check to see if the latest iDKG key needs to be registered, or rotated
                self.check_latest_idkg_dealing_encryption_key_registration_status(
                    registry_version,
                    &registry_public_keys.idkg_dealing_encryption_public_key,
                )
            }
            Err(err) => {
                // One or more node keys were missing from the registry - make a metrics observation
                // and return the first error encountered
                self.metrics.observe_node_key_counts(
                    &KeyCounts::new(registry_public_keys_count, 0, 0),
                    MetricsResult::Err,
                );
                Err(err)
            }
        }
    }

    fn current_node_public_keys(
        &self,
    ) -> Result<CurrentNodePublicKeys, CurrentNodePublicKeysError> {
        let result = self.csp.current_node_public_keys()?;
        Ok(result)
    }

    fn rotate_idkg_dealing_encryption_keys(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<PublicKeyProto, IDkgDealingEncryptionKeyRotationError> {
        let key_rotation_result =
            self.rotate_idkg_dealing_encryption_keys_internal(registry_version);
        self.record_key_rotation_metrics(&key_rotation_result);
        convert_key_rotation_outcome(key_rotation_result)
    }

    fn idkg_dealing_encryption_pubkeys_count(
        &self,
    ) -> Result<usize, IdkgDealingEncPubKeysCountError> {
        let result = self.csp.idkg_dealing_encryption_pubkeys_count()?;
        Ok(result)
    }
}

// Helpers for implementing `KeyManager`-trait.
impl<C: CryptoServiceProvider> CryptoComponentFatClient<C> {
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
        let tls_certificate = tls_certificate_from_registry(
            self.registry_client.as_ref(),
            self.node_id,
            registry_version,
        );
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

    fn check_latest_idkg_dealing_encryption_key_registration_status(
        &self,
        registry_version: RegistryVersion,
        registry_idkg_dealing_encryption_public_key: &PublicKeyProto,
    ) -> CryptoResult<PublicKeyRegistrationStatus> {
        // Get the key rotation period from the subnet config; if it is None, key rotation is disabled
        let key_rotation_period: Duration = if let Some(key_rotation_period) =
            self.get_rotation_period_for_current_node_if_key_rotation_enabled(registry_version)?
        {
            key_rotation_period
        } else {
            info!(
                self.logger,
                "iDKG dealing encryption key rotation not enabled"
            );
            return Ok(PublicKeyRegistrationStatus::AllKeysRegistered);
        };

        // Check if the latest iDKG key we have locally still needs to be registered in the
        // registry, or if it needs to be rotated.
        let current_node_public_keys = match self.current_node_public_keys() {
            Ok(current_node_public_keys) => current_node_public_keys,
            Err(CurrentNodePublicKeysError::TransientInternalError(internal_error)) => {
                return Err(CryptoError::TransientInternalError { internal_error });
            }
        };
        if let Some(latest_local_idkg_dealing_encryption_key) =
            current_node_public_keys.idkg_dealing_encryption_public_key
        {
            if registry_idkg_dealing_encryption_public_key
                .equal_ignoring_timestamp(&latest_local_idkg_dealing_encryption_key)
            {
                self.metrics.observe_boolean_result(
                    BooleanOperation::LatestLocalIdkgKeyExistsInRegistry,
                    BooleanResult::True,
                );
                match registry_idkg_dealing_encryption_public_key.timestamp {
                    None => {
                        // The key in the registry has no timestamp, so it shall be rotated
                        info!(
                            self.logger,
                            "iDKG dealing encryption key has no timestamp and needs rotating"
                        );
                        return Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys);
                    }
                    Some(timestamp_in_millis) => {
                        if self.is_current_key_too_old(timestamp_in_millis, key_rotation_period) {
                            info!(
                                self.logger,
                                "iDKG dealing encryption key too old and needs rotating"
                            );
                            return Ok(
                                PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys,
                            );
                        }
                    }
                }
            } else {
                info!(
                    self.logger,
                    "Local iDKG dealing encryption key needs registration"
                );
                self.metrics.observe_boolean_result(
                    BooleanOperation::LatestLocalIdkgKeyExistsInRegistry,
                    BooleanResult::False,
                );
                return Ok(
                    PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(
                        latest_local_idkg_dealing_encryption_key,
                    ),
                );
            }
        } else {
            panic!("No iDKG dealing encryption key found locally");
        }
        Ok(PublicKeyRegistrationStatus::AllKeysRegistered)
    }

    fn rotate_idkg_dealing_encryption_keys_internal(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<KeyRotationOutcome, IDkgDealingEncryptionKeyRotationError> {
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

        let current_idkg_public_key_proto = self.current_node_public_keys()?.idkg_dealing_encryption_public_key
            .expect("missing local IDKG public key! \
            This should not happen because it's expected that check_keys_with_registry() was called before \
            to ensure that rotation was needed.");
        let idkg_public_key_from_registry = fetch_idkg_dealing_encryption_public_key_from_registry(
            &self.node_id,
            self.registry_client.as_ref(),
            registry_version,
        );
        match idkg_public_key_from_registry {
            Ok(registry_idkg_public_key_proto) => {
                if !registry_idkg_public_key_proto
                    .equal_ignoring_timestamp(&current_idkg_public_key_proto)
                {
                    return Ok(KeyRotationOutcome::KeyNotRotated {
                        existing_key: current_idkg_public_key_proto,
                    });
                }
                match registry_idkg_public_key_proto.timestamp {
                    None => Ok(KeyRotationOutcome::KeyRotated {
                        new_key: idkg_dealing_encryption_pk_to_proto(
                            self.csp.idkg_gen_dealing_encryption_key_pair()?,
                        ),
                    }),
                    Some(timestamp_in_millis) => {
                        if self.is_current_key_too_old(timestamp_in_millis, key_rotation_period) {
                            Ok(KeyRotationOutcome::KeyRotated {
                                new_key: idkg_dealing_encryption_pk_to_proto(
                                    self.csp.idkg_gen_dealing_encryption_key_pair()?,
                                ),
                            })
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
                Ok(KeyRotationOutcome::RegistryKeyBadOrMissing {
                    existing_key: current_idkg_public_key_proto,
                })
            }
            Err(error @ MegaKeyFromRegistryError::UnsupportedAlgorithm { .. }) => {
                error!(
                    self.logger,
                    "IDKG dealing encryption public key from registry uses an unsupported algorithm {:?}", error
                );
                Ok(KeyRotationOutcome::RegistryKeyBadOrMissing {
                    existing_key: current_idkg_public_key_proto,
                })
            }

            Err(error @ MegaKeyFromRegistryError::MalformedPublicKey { .. }) => {
                error!(
                    self.logger,
                    "IDKG dealing encryption public key from registry is malformed {:?}", error
                );
                Ok(KeyRotationOutcome::RegistryKeyBadOrMissing {
                    existing_key: current_idkg_public_key_proto,
                })
            }
        }
    }

    fn record_key_rotation_metrics(
        &self,
        key_rotation_result: &Result<KeyRotationOutcome, IDkgDealingEncryptionKeyRotationError>,
    ) {
        match key_rotation_result {
            Ok(outcome) => {
                match outcome {
                    KeyRotationOutcome::KeyRotated { .. } => {
                        self.metrics
                            .observe_key_rotation_result(KeyRotationResult::KeyRotated);
                        self.metrics.observe_boolean_result(
                            BooleanOperation::LatestLocalIdkgKeyExistsInRegistry,
                            BooleanResult::False,
                        );
                    }
                    KeyRotationOutcome::KeyNotRotated { .. } => {
                        self.metrics
                            .observe_key_rotation_result(KeyRotationResult::KeyNotRotated);
                    }
                    KeyRotationOutcome::RegistryKeyBadOrMissing { .. } => {
                        self.metrics.observe_key_rotation_result(
                            KeyRotationResult::RegistryKeyBadOrMissing,
                        );
                    }
                };
            }
            Err(err) => match err {
                IDkgDealingEncryptionKeyRotationError::LatestLocalRotationTooRecent => {
                    self.metrics.observe_key_rotation_result(
                        KeyRotationResult::LatestLocalRotationTooRecent,
                    );
                    self.metrics.observe_boolean_result(
                        BooleanOperation::LatestLocalIdkgKeyExistsInRegistry,
                        BooleanResult::True,
                    );
                }
                IDkgDealingEncryptionKeyRotationError::KeyGenerationError(_) => {
                    self.metrics
                        .observe_key_rotation_result(KeyRotationResult::KeyGenerationError);
                }
                IDkgDealingEncryptionKeyRotationError::RegistryError(_) => {
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
            },
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
                    .get_ecdsa_config(subnet_id, registry_version)
                {
                    Ok(Some(config)) if !config.key_ids.is_empty() => {
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
        timestamp_in_millis: u64,
        key_rotation_period: Duration,
    ) -> bool {
        let time_of_registration = Time::from_millis_since_unix_epoch(timestamp_in_millis)
            .expect("conversion error to happen in the year 2554");
        if let Some(time_to_rotate) = time_of_registration.checked_add_duration(key_rotation_period)
        {
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
            self.metrics.observe_boolean_result(
                BooleanOperation::KeyInRegistryMissingLocally,
                BooleanResult::True,
            );
        }
    }

    fn observe_number_of_idkg_dealing_encryption_public_keys(&self) {
        match self.idkg_dealing_encryption_pubkeys_count() {
            Ok(num_idkg_dealing_encryption_pubkeys) => {
                self.metrics.observe_idkg_dealing_encryption_pubkey_count(
                    num_idkg_dealing_encryption_pubkeys,
                    MetricsResult::Ok,
                );
            }
            Err(IdkgDealingEncPubKeysCountError::TransientInternalError(internal_error)) => {
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

const PUBLIC_KEY_TYPE_COUNT: u32 = 5;

enum KeyRotationOutcome {
    KeyRotated { new_key: PublicKeyProto },
    KeyNotRotated { existing_key: PublicKeyProto },
    RegistryKeyBadOrMissing { existing_key: PublicKeyProto },
}

fn convert_key_rotation_outcome(
    key_rotation_result: Result<KeyRotationOutcome, IDkgDealingEncryptionKeyRotationError>,
) -> Result<PublicKeyProto, IDkgDealingEncryptionKeyRotationError> {
    match key_rotation_result {
        Ok(outcome) => {
            let public_key_proto = match outcome {
                KeyRotationOutcome::KeyRotated { new_key } => new_key,
                KeyRotationOutcome::KeyNotRotated { existing_key } => existing_key,
                KeyRotationOutcome::RegistryKeyBadOrMissing { existing_key } => existing_key,
            };
            Ok(public_key_proto)
        }
        Err(err) => Err(err),
    }
}
