use crate::keygen::utils::dkg_dealing_encryption_pk_to_proto;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreError};
use crate::threshold::ni_dkg::specialise;
use crate::threshold::ni_dkg::{NIDKG_FS_SCOPE, NIDKG_THRESHOLD_SCOPE};
use crate::types::{CspPublicCoefficients, CspSecretKey};
use crate::vault::api::NiDkgCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::KeyId;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381 as ni_dkg_clib;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::SecretKey;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::NodeIndex;
use ic_logger::debug;
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, NumberOfNodes};
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore> NiDkgCspVault
    for LocalCspVault<R, S, C, P>
{
    fn gen_dealing_encryption_key_pair(
        &self,
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), ni_dkg_errors::CspDkgCreateFsKeyError>
    {
        debug!(self.logger; crypto.method_name => "gen_dealing_encryption_key_pair");

        // Get state
        let seed = Seed::from_rng(&mut *self.rng_write_lock());
        // Call lib:
        let key_set = ni_dkg_clib::create_forward_secure_key_pair(seed, node_id.get().as_slice());

        // Generalise over fs key variants:
        let public_key = CspFsEncryptionPublicKey::Groth20_Bls12_381(key_set.public_key);
        let pop = CspFsEncryptionPop::Groth20WithPop_Bls12_381(key_set.pop);
        let key_set = CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set);

        // Update state:
        self.store_secret_key(
            KeyId::from(&public_key),
            CspSecretKey::FsEncryption(key_set),
            None,
        )
        .map_err(|e| match e {
            SecretKeyStoreError::DuplicateKeyId(key_id) => {
                ni_dkg_errors::CspDkgCreateFsKeyError::DuplicateKeyId(
                    format!("duplicate ni-dkg dealing encryption secret key id: {}", key_id))
            },
            SecretKeyStoreError::PersistenceError(io_error) => {
                ni_dkg_errors::CspDkgCreateFsKeyError::TransientInternalError(
                    format!("error persisting ni-dkg dealing encryption secret key: {}", io_error),
                )
            }
        })
        .and_then(|()| {
            self.public_key_store_write_lock()
                .set_once_ni_dkg_dealing_encryption_pubkey(dkg_dealing_encryption_pk_to_proto(
                    public_key,
                    pop,
                ))
                .map_err(|e| match e {
                    PublicKeySetOnceError::AlreadySet => {
                        ni_dkg_errors::CspDkgCreateFsKeyError::InternalError(
                            ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError {
                            internal_error: "ni-dkg dealing encryption public key already set"
                                .to_string(),
                        })
                    }
                    PublicKeySetOnceError::Io(io_error) => {
                        ni_dkg_errors::CspDkgCreateFsKeyError::TransientInternalError(
                            format!("error persisting ni-dkg dealing encryption public key: {}", io_error),
                        )
                    }
                })
        })?;
        // FIN:
        Ok((public_key, pop))
    }

    fn update_forward_secure_epoch(
        &self,
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch: Epoch,
    ) -> Result<(), ni_dkg_errors::CspDkgUpdateFsEpochError> {
        debug!(self.logger; crypto.method_name => "update_forward_secure_epoch", crypto.dkg_epoch => epoch.get());
        let start_time = self.metrics.now();

        let result = self.update_forward_secure_epoch_internal(algorithm_id, key_id, epoch);
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
            MetricsScope::Local,
            "update_forward_secure_epoch",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: &BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        maybe_resharing_secret_key_id: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError> {
        debug!(self.logger; crypto.method_name => "create_dealing", crypto.dkg_epoch => epoch.get());
        let start_time = self.metrics.now();
        let result = self.create_dealing_internal(
            algorithm_id,
            dealer_index,
            threshold,
            epoch,
            receiver_keys,
            maybe_resharing_secret_key_id,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
            MetricsScope::Local,
            "create_dealing",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn load_threshold_signing_key(
        &self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        fs_key_id: KeyId,
        receiver_index: NodeIndex,
    ) -> Result<(), ni_dkg_errors::CspDkgLoadPrivateKeyError> {
        debug!(self.logger; crypto.method_name => "load_threshold_signing_key", crypto.dkg_epoch => epoch.get());
        let start_time = self.metrics.now();
        let result = self.load_threshold_signing_key_internal(
            algorithm_id,
            epoch,
            csp_transcript,
            fs_key_id,
            receiver_index,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
            MetricsScope::Local,
            "load_threshold_signing_key",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn retain_threshold_keys_if_present(
        &self,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), ni_dkg_errors::CspDkgRetainThresholdKeysError> {
        debug!(self.logger; crypto.method_name => "retain_threshold_keys_if_present");
        let start_time = self.metrics.now();
        self.sks_write_lock()
            .retain(
                move |key_id, _| active_key_ids.contains(key_id),
                NIDKG_THRESHOLD_SCOPE,
            )
            .unwrap_or_else(|e| panic!("error retaining threshold keys: {}", e));
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
            MetricsScope::Local,
            "retain_threshold_keys_if_present",
            MetricsResult::Ok,
            start_time,
        );
        Ok(())
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn update_forward_secure_epoch_internal(
        &self,
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch: Epoch,
    ) -> Result<(), ni_dkg_errors::CspDkgUpdateFsEpochError> {
        debug!(self.logger; crypto.method_name => "update_forward_secure_epoch", crypto.dkg_epoch => epoch.get());

        let updated_key_set = match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                // Retrieve key from key store
                let maybe_key_set = self.sks_read_lock().get(&key_id);
                let key_set = maybe_key_set.ok_or_else(|| {
                    ni_dkg_errors::CspDkgUpdateFsEpochError::FsKeyNotInSecretKeyStoreError(
                        ni_dkg_errors::KeyNotFoundError {
                            internal_error: "Cannot update forward secure key if it is missing"
                                .to_string(),
                            key_id: key_id.to_string(),
                        },
                    )
                })?;

                // Specialise to Groth20
                let key_set = specialise::fs_key_set(key_set)
                    .expect("Not a forward secure secret key; it should be impossible to retrieve a key of the wrong type.");
                let mut key_set = specialise::groth20::fs_key_set(key_set)
                    .expect("If key generation is correct, it should be impossible to retrieve a key of the wrong type.");

                // Update secret key to new epoch (deserialize key first)
                let mut secret_key = SecretKey::deserialize(&key_set.secret_key);
                let seed = Seed::from_rng(&mut *self.rng_write_lock());
                ni_dkg_clib::update_key_inplace_to_epoch(&mut secret_key, epoch, seed);

                // Replace secret key in key set (serialize key first)
                key_set.secret_key = secret_key.serialize();

                // Generalise:
                Ok(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set))
            }
            other => Err(ni_dkg_errors::CspDkgUpdateFsEpochError::UnsupportedAlgorithmId(other)),
        };

        // Save state
        self.sks_write_lock()
            .insert_or_replace(
                key_id,
                CspSecretKey::FsEncryption(updated_key_set?),
                Some(NIDKG_FS_SCOPE),
            )
            .unwrap_or_else(|e| panic!("Error updating forward secure epoch: {}", e));

        // FIN
        Ok(())
    }

    fn create_dealing_internal(
        &self,
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: &BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        maybe_resharing_secret_key_id: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError> {
        // If re-sharing, fetch the secret key from the Secret Key Store.
        let maybe_resharing_secret_key = match maybe_resharing_secret_key_id {
            Some(key_id) => {
                let maybe_secret_key: Option<CspSecretKey> = self.sks_read_lock().get(&key_id);
                let secret_key = maybe_secret_key.ok_or_else(|| {
                    ni_dkg_errors::CspDkgCreateReshareDealingError::ReshareKeyNotInSecretKeyStoreError(
                        ni_dkg_errors::KeyNotFoundError {
                            internal_error: format!(
                                "Cannot find threshold key to be reshared:\n  key id: {}\n  Epoch:  {}",
                                key_id, epoch
                            ),
                            key_id: key_id.to_string(),
                        },
                    )
                })?;
                Some(secret_key)
            }
            None => None,
        };
        // Specialisation to this scheme:
        let result = match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                let maybe_resharing_secret_key_bytes = match maybe_resharing_secret_key {
                    Some(secret_key) => {
                        let secret_key_bytes = specialise::groth20::threshold_secret_key(
                            secret_key,
                        )
                        .map_err(ni_dkg_errors::CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError)?;
                        Some(secret_key_bytes)
                    }
                    None => None,
                };
                let receiver_keys = specialise::groth20::receiver_keys(receiver_keys).map_err(
                    |(receiver_index, error)| {
                        ni_dkg_errors::CspDkgCreateReshareDealingError::MalformedFsPublicKeyError {
                            receiver_index,
                            error,
                        }
                    },
                )?;
                // Stateless call to crypto lib
                // Acquire an rng lock and generate randomness before invoking create_dealing
                // because:
                // * acquiring two locks inline in the create_dealing call would lead to a
                //   deadlock.
                // * we should not hold the write lock for the whole duration of create_dealing.
                let (keygen_seed, encryption_seed) = {
                    let mut rng = self.rng_write_lock();
                    (Seed::from_rng(&mut *rng), Seed::from_rng(&mut *rng))
                };
                let dealing = ni_dkg_clib::create_dealing(
                    keygen_seed,
                    encryption_seed,
                    threshold,
                    &receiver_keys,
                    epoch,
                    dealer_index,
                    maybe_resharing_secret_key_bytes,
                )?;
                // Response
                Ok(CspNiDkgDealing::Groth20_Bls12_381(dealing))
            }
            other => {
                Err(ni_dkg_errors::CspDkgCreateReshareDealingError::UnsupportedAlgorithmId(other))
            }
        };
        result
    }

    fn load_threshold_signing_key_internal(
        &self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        fs_key_id: KeyId,
        receiver_index: NodeIndex,
    ) -> Result<(), ni_dkg_errors::CspDkgLoadPrivateKeyError> {
        let result = match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                let threshold_key_id = KeyId::from(&CspPublicCoefficients::from(&csp_transcript));

                // Convert types
                let transcript = specialise::groth20::transcript(csp_transcript)
                    .map_err(ni_dkg_errors::CspDkgLoadPrivateKeyError::MalformedTranscriptError)?;

                // Check if threshold key has been computed already
                let threshold_secret_key: Option<CspSecretKey> =
                    self.sks_read_lock().get(&threshold_key_id);
                if let Some(secret_key) = threshold_secret_key {
                    // this adds a sanity check to ensure the key is well formed:
                    return specialise::groth20::threshold_secret_key(secret_key)
                        .map(|_| ())
                        .map_err(
                            ni_dkg_errors::CspDkgLoadPrivateKeyError::MalformedSecretKeyError,
                        );
                }

                // Compute the key
                let fs_decryption_key = {
                    let maybe_key_set = self.sks_read_lock().get(&fs_key_id);
                    let key_set = maybe_key_set.ok_or_else(||
                        ni_dkg_errors::CspDkgLoadPrivateKeyError::KeyNotFoundError(
                            // TODO (CRP-820): This name is inconsistent with the other error enums,
                            // where this is now called FsKeyNotInSecretKeyStoreError or some
                            // such paragraph-of-a-name.
                            ni_dkg_errors::KeyNotFoundError {
                                internal_error: "Cannot decrypt shares if the forward secure key encryption key is missing".to_string(),
                                key_id: fs_key_id.to_string(),
                            },
                        )
                    )?;

                    let raw_fs_key_set =
                        specialise::groth20::fs_key_set(
                            specialise::fs_key_set(key_set).expect("Not a forward secure secret key; it should be impossible to retrieve a key of the wrong type.")
                        ).expect("If key generation is correct, it should be impossible to retrieve a key of the wrong type.");

                    SecretKey::deserialize(&raw_fs_key_set.secret_key)
                };

                let csp_secret_key = ni_dkg_clib::compute_threshold_signing_key(
                    &transcript,
                    receiver_index,
                    &fs_decryption_key,
                    epoch,
                )
                .map(CspSecretKey::ThresBls12_381)?;

                let result = self.sks_write_lock().insert(
                    threshold_key_id,
                    csp_secret_key,
                    Some(NIDKG_THRESHOLD_SCOPE),
                );
                match result {
                    Ok(()) => Ok(()),
                    Err(SecretKeyStoreError::DuplicateKeyId(_key_id)) => Ok(()),
                    Err(SecretKeyStoreError::PersistenceError(e)) => {
                        panic!("Error persisting secret key store while loading threshold signing key: {}", e)
                    }
                }
            }
            other => Err(ni_dkg_errors::CspDkgLoadPrivateKeyError::UnsupportedAlgorithmId(other)),
        };
        result
    }
}
