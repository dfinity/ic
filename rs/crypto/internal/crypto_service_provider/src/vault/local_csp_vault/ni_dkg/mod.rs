use crate::KeyId;
use crate::key_id::KeyIdInstantiationError;
use crate::keygen::utils::dkg_dealing_encryption_pk_to_proto;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreInsertionError};
use crate::threshold::ni_dkg::specialise;
use crate::threshold::ni_dkg::{NIDKG_FS_SCOPE, NIDKG_THRESHOLD_SCOPE};
use crate::types::{CspPublicCoefficients, CspSecretKey};
use crate::vault::api::NiDkgCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateFsKeyError, CspDkgLoadPrivateKeyError, InternalError,
};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381 as ni_dkg_clib;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::SecretKey;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::types::FsEncryptionKeySetWithPop;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_crypto_internal_types::NodeIndex;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_node_key_validation::ValidDkgDealingEncryptionPublicKey;
use ic_logger::debug;
use ic_protobuf::registry::crypto::v1::PublicKey;
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
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        debug!(self.logger; crypto.method_name => "gen_dealing_encryption_key_pair");
        let start_time = self.metrics.now();
        let result = self.gen_dealing_encryption_key_pair_internal(node_id);
        self.metrics.observe_duration_seconds(
            MetricsDomain::NiDkgAlgorithm,
            MetricsScope::Local,
            "gen_dealing_encryption_key_pair",
            MetricsResult::from(&result),
            start_time,
        );
        result
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
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        maybe_resharing_secret_key_id: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError> {
        debug!(self.logger; crypto.method_name => "create_dealing", crypto.dkg_epoch => epoch.get());
        let start_time = self.metrics.now();
        let result = self.create_dealing_internal(
            algorithm_id,
            dealer_index,
            threshold,
            epoch,
            &receiver_keys,
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
        let filter = move |key_id: &KeyId, _: &CspSecretKey| active_key_ids.contains(key_id);
        if self
            .sks_read_lock()
            .retain_would_modify_keystore(filter.clone(), NIDKG_THRESHOLD_SCOPE)
        {
            // The fact that we perform the initial check holding a read lock on the SKS, and then
            // possibly acquire a write lock to actually modify the SKS, results in a potential
            // race condition here. This has two consequences:
            //  - In case another writer managed to get the write lock after we released the read
            //    lock and acquired the write lock, and also executed the retain operation with the
            //    same set of `active_key_ids`, this is fine, since the operation is idempotent.
            //  - Another potential issue is that a new transcript could have been loaded, and a
            //    new key added, between the time that retain on the crypto component was called,
            //    and the time that we actually call retain here. However:
            //     - This issue is neither fixed, nor exacerbated by the race condition here
            //     - The issue is tracked in CRP-1094: It is currently not a problem due to how
            //       these functions are called from consensus
            self.sks_write_lock()
                .retain(filter, NIDKG_THRESHOLD_SCOPE)
                .unwrap_or_else(|e| panic!("error retaining threshold keys: {e}"));
        }
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
    fn gen_dealing_encryption_key_pair_internal(
        &self,
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        let seed = self.generate_seed();
        let (public_key, pop, key_set) = gen_dealing_encryption_key_pair_from_seed(node_id, seed);
        let key_id = KeyId::from(&public_key);
        let secret_key = CspSecretKey::FsEncryption(key_set);
        let public_key_proto = dkg_dealing_encryption_pk_to_proto(public_key, pop);
        let valid_public_key = validate_dealing_encryption_public_key(node_id, public_key_proto)?;
        self.store_dealing_encryption_key_pair(key_id, secret_key, valid_public_key.get().clone())?;
        Ok((public_key, pop))
    }

    fn store_dealing_encryption_key_pair(
        &self,
        key_id: KeyId,
        secret_key: CspSecretKey,
        public_key_proto: PublicKey,
    ) -> Result<(), CspDkgCreateFsKeyError> {
        let (mut sks_write_lock, mut pks_write_lock) = self.sks_and_pks_write_locks();
        sks_write_lock
            .insert(key_id, secret_key, None)
            .map_err(|e| match e {
                SecretKeyStoreInsertionError::DuplicateKeyId(key_id) => {
                    CspDkgCreateFsKeyError::DuplicateKeyId(format!(
                        "duplicate ni-dkg dealing encryption secret key id: {key_id}"
                    ))
                }
                SecretKeyStoreInsertionError::TransientError(io_error) => {
                    CspDkgCreateFsKeyError::TransientInternalError(format!(
                        "error persisting ni-dkg dealing encryption secret key: {io_error}"
                    ))
                }
                SecretKeyStoreInsertionError::SerializationError(serialization_error) => {
                    CspDkgCreateFsKeyError::InternalError(InternalError {
                        internal_error: format!(
                            "error persisting ni-dkg dealing encryption secret key: {serialization_error}"
                        ),
                    })
                }
            })
            .and_then(|()| {
                pks_write_lock
                    .set_once_ni_dkg_dealing_encryption_pubkey(public_key_proto)
                    .map_err(|e| match e {
                        PublicKeySetOnceError::AlreadySet => {
                            CspDkgCreateFsKeyError::InternalError(InternalError {
                                internal_error: "ni-dkg dealing encryption public key already set"
                                    .to_string(),
                            })
                        }
                        PublicKeySetOnceError::Io(io_error) => {
                            CspDkgCreateFsKeyError::TransientInternalError(format!(
                                "error persisting ni-dkg dealing encryption public key: {io_error}"
                            ))
                        }
                    })
            })
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn update_forward_secure_epoch_internal(
        &self,
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch_to_update_to: Epoch,
    ) -> Result<(), ni_dkg_errors::CspDkgUpdateFsEpochError> {
        debug!(self.logger; crypto.method_name => "update_forward_secure_epoch", crypto.dkg_epoch => epoch_to_update_to.get());

        if algorithm_id != AlgorithmId::NiDkg_Groth20_Bls12_381 {
            return Err(
                ni_dkg_errors::CspDkgUpdateFsEpochError::UnsupportedAlgorithmId(algorithm_id),
            );
        }

        // Retrieve key from key store
        let maybe_key_set = self.sks_read_lock().get(&key_id);
        let (mut key_set, mut secret_key) =
            specialize_key_set_and_deserialize_secret_key(key_id, maybe_key_set)?;

        if let Some(epoch_in_sks) = secret_key.current_epoch() {
            if epoch_to_update_to <= epoch_in_sks {
                // Epoch we want to update to is older than or equal to that of the key in the SKS
                // => nothing to do; return early.
                return Ok(());
            }

            // Epoch we want to update to is newer than that of the key in the SKS
            // => try to update the key in the SKS
            // Generate the seed and release the `rng_write_lock` before acquiring the SKS write
            // lock, since if we were to hold both locks at the same time, we would have to adhere
            // to the lock acquisition order.
            let seed = Seed::from_rng(&mut *self.rng_write_lock());
            // Optimistically update the key, even though we may have to throw it away in case the
            // key in the SKS was updated to the `epoch_to_update_to` (or newer) in the meantime -
            // the alternative would be to update the key while holding the SKS write lock, and
            // this is not desirable since the key update is an expensive and relatively
            // long-running operation.
            ni_dkg_clib::update_key_inplace_to_epoch(&mut secret_key, epoch_to_update_to, seed);
            // Replace secret key in key set (serialize key first)
            key_set.secret_key = secret_key.serialize();
            // Generalise:
            let key_set = CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set);

            let mut sks_write_lock = self.sks_write_lock();
            let maybe_reread_key_set = sks_write_lock.get(&key_id);
            let (_reread_key_set, reread_secret_key) =
                specialize_key_set_and_deserialize_secret_key(key_id, maybe_reread_key_set)?;
            if let Some(reread_epoch_in_sks) = reread_secret_key.current_epoch()
                && epoch_to_update_to > reread_epoch_in_sks
            {
                // Epoch to update to is still newer than the one of the key in the SKS
                // => update the key in the SKS
                sks_write_lock
                    .insert_or_replace(
                        key_id,
                        CspSecretKey::FsEncryption(key_set),
                        Some(NIDKG_FS_SCOPE),
                    )
                    .unwrap_or_else(|e| panic!("Error updating forward secure epoch: {e}"));
            }
        }
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
                                "Cannot find threshold key to be reshared:\n  key id: {key_id}\n  Epoch:  {epoch}"
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

        match algorithm_id {
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
        }
    }

    fn load_threshold_signing_key_internal(
        &self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        fs_key_id: KeyId,
        receiver_index: NodeIndex,
    ) -> Result<(), ni_dkg_errors::CspDkgLoadPrivateKeyError> {
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                let threshold_key_id =
                    KeyId::try_from(&CspPublicCoefficients::from(&csp_transcript)).map_err(
                        |key_id_instantiation_error| match key_id_instantiation_error {
                            KeyIdInstantiationError::InvalidArguments(internal_error) => {
                                CspDkgLoadPrivateKeyError::KeyIdInstantiationError(internal_error)
                            }
                        },
                    )?;

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
                    Err(SecretKeyStoreInsertionError::DuplicateKeyId(_key_id)) => Ok(()),
                    Err(SecretKeyStoreInsertionError::TransientError(e)) => Err(
                        CspDkgLoadPrivateKeyError::TransientInternalError(InternalError {
                            internal_error: format!(
                                "error persisting secret key store while loading threshold signing key: {e}"
                            ),
                        }),
                    ),
                    Err(SecretKeyStoreInsertionError::SerializationError(e)) => {
                        Err(CspDkgLoadPrivateKeyError::InternalError(InternalError {
                            internal_error: format!(
                                "error serializing secret key store while loading threshold signing key: {e}"
                            ),
                        }))
                    }
                }
            }
            other => Err(ni_dkg_errors::CspDkgLoadPrivateKeyError::UnsupportedAlgorithmId(other)),
        }
    }
}

fn gen_dealing_encryption_key_pair_from_seed(
    node_id: NodeId,
    seed: Seed,
) -> (
    CspFsEncryptionPublicKey,
    CspFsEncryptionPop,
    CspFsEncryptionKeySet,
) {
    let key_set = ni_dkg_clib::create_forward_secure_key_pair(seed, node_id.get().as_slice());
    let public_key = CspFsEncryptionPublicKey::Groth20_Bls12_381(key_set.public_key);
    let pop = CspFsEncryptionPop::Groth20WithPop_Bls12_381(key_set.pop);
    let key_set = CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set);
    (public_key, pop, key_set)
}

fn specialize_key_set_and_deserialize_secret_key(
    key_id: KeyId,
    maybe_key_set: Option<CspSecretKey>,
) -> Result<(FsEncryptionKeySetWithPop, SecretKey), ni_dkg_errors::CspDkgUpdateFsEpochError> {
    let key_set = maybe_key_set.ok_or_else(|| {
        ni_dkg_errors::CspDkgUpdateFsEpochError::FsKeyNotInSecretKeyStoreError(
            ni_dkg_errors::KeyNotFoundError {
                internal_error: "Cannot update forward secure key if it is missing".to_string(),
                key_id: key_id.to_string(),
            },
        )
    })?;

    // Specialise to Groth20
    let key_set = specialise::fs_key_set(key_set)
        .expect("Not a forward secure secret key; it should be impossible to retrieve a key of the wrong type.");
    let key_set = specialise::groth20::fs_key_set(key_set)
        .expect("If key generation is correct, it should be impossible to retrieve a key of the wrong type.");

    // Update secret key to new epoch (deserialize key first)
    let secret_key = SecretKey::deserialize(&key_set.secret_key);
    Ok((key_set, secret_key))
}
fn validate_dealing_encryption_public_key(
    node_id: NodeId,
    public_key_proto: PublicKey,
) -> Result<ValidDkgDealingEncryptionPublicKey, CspDkgCreateFsKeyError> {
    ValidDkgDealingEncryptionPublicKey::try_from((public_key_proto, node_id)).map_err(|error| {
        CspDkgCreateFsKeyError::InternalError(InternalError {
            internal_error: format!(
                "NI-DKG dealing encryption public key validation error: {error}"
            ),
        })
    })
}
