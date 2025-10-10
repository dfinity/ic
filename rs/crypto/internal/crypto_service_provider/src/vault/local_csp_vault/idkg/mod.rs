use crate::api::CspCreateMEGaKeyError;
use crate::canister_threshold::{IDKG_MEGA_SCOPE, IDKG_THRESHOLD_KEYS_SCOPE};
use crate::key_id::KeyId;
use crate::keygen::utils::{
    MEGaPublicKeyFromProtoError, idkg_dealing_encryption_pk_to_proto, mega_public_key_from_proto,
};
use crate::public_key_store::{
    PublicKeyAddError, PublicKeyRetainCheckError, PublicKeyRetainError, PublicKeyStore,
};
use crate::secret_key_store::{
    SecretKeyStore, SecretKeyStoreInsertionError, SecretKeyStoreWriteError,
};
use crate::types::CspSecretKey;
use crate::vault::api::{
    IDkgCreateDealingVaultError, IDkgDealingInternalBytes, IDkgProtocolCspVault,
    IDkgTranscriptInternalBytes, IDkgTranscriptOperationInternalBytes,
};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    CommitmentOpening, CommitmentOpeningBytes, EccCurveType, IDkgComplaintInternal,
    IDkgComputeSecretSharesInternalError, IDkgComputeSecretSharesWithOpeningsInternalError,
    IDkgDealingInternal, IDkgTranscriptInternal, IDkgTranscriptOperationInternal,
    MEGaKeySetK256Bytes, MEGaPrivateKey, MEGaPrivateKeyK256Bytes, MEGaPublicKey,
    MEGaPublicKeyK256Bytes, PolynomialCommitment, SecretShares, Seed, compute_secret_shares,
    compute_secret_shares_with_openings, create_dealing as clib_create_dealing, gen_keypair,
    generate_complaints, open_dealing, privately_verify_dealing,
};
use ic_crypto_node_key_validation::ValidIDkgDealingEncryptionPublicKey;
use ic_logger::debug;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgLoadTranscriptError, IDkgOpenTranscriptError, IDkgRetainKeysError,
    IDkgVerifyDealingPrivateError,
};
use ic_types::crypto::canister_threshold_sig::idkg::BatchSignedIDkgDealing;
use ic_types::{NodeIndex, NumberOfNodes};
use parking_lot::{RwLockReadGuard, RwLockWriteGuard};
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    IDkgProtocolCspVault for LocalCspVault<R, S, C, P>
{
    fn idkg_create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        context_data: Vec<u8>,
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: Vec<PublicKey>,
        transcript_operation_internal_bytes: IDkgTranscriptOperationInternalBytes,
    ) -> Result<IDkgDealingInternalBytes, IDkgCreateDealingVaultError> {
        debug!(self.logger; crypto.method_name => "idkg_create_dealing");
        let start_time = self.metrics.now();
        let receiver_keys_typed = receiver_keys
            .into_iter()
            .enumerate()
            .map(|(receiver_index_usize, pk_proto)| {
                mega_public_key_from_proto(&pk_proto).map_err(|e| match e {
                    MEGaPublicKeyFromProtoError::MalformedPublicKey { key_bytes } => {
                        u32::try_from(receiver_index_usize).ok().map_or_else(
                            || {
                                IDkgCreateDealingVaultError::InternalError(format!(
                                    "node index is larger than u32: {receiver_index_usize}"
                                ))
                            },
                            |receiver_index| IDkgCreateDealingVaultError::MalformedPublicKey {
                                receiver_index,
                                key_bytes,
                            },
                        )
                    }
                    MEGaPublicKeyFromProtoError::UnsupportedAlgorithm { algorithm_id } => {
                        IDkgCreateDealingVaultError::UnsupportedAlgorithm(algorithm_id)
                    }
                })
            })
            .collect::<Result<Vec<_>, IDkgCreateDealingVaultError>>()?;
        let transcript_operation_internal =
            IDkgTranscriptOperationInternal::try_from(&transcript_operation_internal_bytes)
                .map_err(|e| IDkgCreateDealingVaultError::SerializationError(e.0))?;
        let result = self.idkg_create_dealing_internal(
            algorithm_id,
            &context_data,
            dealer_index,
            reconstruction_threshold,
            &receiver_keys_typed[..],
            &transcript_operation_internal,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Local,
            "idkg_create_dealing",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn idkg_verify_dealing_private(
        &self,
        algorithm_id: AlgorithmId,
        dealing: IDkgDealingInternalBytes,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: Vec<u8>,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        debug!(self.logger; crypto.method_name => "idkg_verify_dealing_private");
        let start_time = self.metrics.now();
        let internal_dealing = IDkgDealingInternal::deserialize(dealing.as_ref()).map_err(|e| {
            IDkgVerifyDealingPrivateError::InvalidArgument(format!(
                "failed to deserialize internal dealing: {e:?}"
            ))
        })?;
        let result = self.idkg_verify_dealing_private_internal(
            algorithm_id,
            &internal_dealing,
            dealer_index,
            receiver_index,
            receiver_key_id,
            &context_data,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Local,
            "idkg_verify_dealing_private",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn idkg_load_transcript(
        &self,
        algorithm_id: AlgorithmId,
        dealings: BTreeMap<NodeIndex, IDkgDealingInternalBytes>,
        context_data: Vec<u8>,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        let start_time = self.metrics.now();
        let internal_dealings = idkg_internal_dealings_from_bytes(&dealings)?;
        let internal_transcript = IDkgTranscriptInternal::deserialize(transcript.as_ref())
            .map_err(|e| IDkgLoadTranscriptError::SerializationError {
                internal_error: format!("failed to deserialize internal transcript: {:?}", e.0),
            })?;
        let result = self.idkg_load_transcript_internal(
            algorithm_id,
            &internal_dealings,
            &context_data,
            receiver_index,
            &key_id,
            &internal_transcript,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Local,
            "idkg_load_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn idkg_load_transcript_with_openings(
        &self,
        alg: AlgorithmId,
        dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        openings: BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: Vec<u8>,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<(), IDkgLoadTranscriptError> {
        let start_time = self.metrics.now();
        let internal_dealings = idkg_internal_dealings_from_verified_dealings(&dealings)?;
        let internal_transcript = IDkgTranscriptInternal::deserialize(transcript.as_ref())
            .map_err(|e| IDkgLoadTranscriptError::SerializationError {
                internal_error: format!("failed to deserialize internal transcript: {:?}", e.0),
            })?;
        let result = self.idkg_load_transcript_with_openings_internal(
            alg,
            &internal_dealings,
            &openings,
            &context_data,
            receiver_index,
            &key_id,
            &internal_transcript,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Local,
            "idkg_load_transcript_with_openings",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        debug!(self.logger; crypto.method_name => "idkg_gen_dealing_encryption_key_pair");
        let start_time = self.metrics.now();
        let result = self.idkg_gen_dealing_encryption_key_pair_internal();
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Local,
            "idkg_gen_dealing_encryption_key_pair",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn idkg_open_dealing(
        &self,
        alg: AlgorithmId,
        dealing: BatchSignedIDkgDealing,
        dealer_index: NodeIndex,
        context_data: Vec<u8>,
        opener_index: NodeIndex,
        opener_key_id: KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
        let start_time = self.metrics.now();
        let internal_dealing = IDkgDealingInternal::try_from(&dealing).map_err(|e| {
            IDkgOpenTranscriptError::InternalError {
                internal_error: format!(
                    "Error deserializing a signed dealing: {e:?} of dealer {dealer_index:?}"
                ),
            }
        })?;
        let result = self.idkg_open_dealing_internal(
            alg,
            internal_dealing,
            dealer_index,
            &context_data,
            opener_index,
            &opener_key_id,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Local,
            "idkg_open_dealing",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    fn idkg_retain_active_keys(
        &self,
        active_key_ids: BTreeSet<KeyId>,
        oldest_public_key: MEGaPublicKey,
    ) -> Result<(), IDkgRetainKeysError> {
        debug!(self.logger; crypto.method_name => "idkg_retain_active_keys");
        let start_time = self.metrics.now();
        let result = self.idkg_retain_active_keys_internal(active_key_ids, oldest_public_key);
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Local,
            "idkg_retain_active_keys",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn idkg_create_dealing_internal(
        &self,
        algorithm_id: AlgorithmId,
        context_data: &[u8],
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: &[MEGaPublicKey],
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternalBytes, IDkgCreateDealingVaultError> {
        let shares = self.get_secret_shares(transcript_operation)?;
        let seed = Seed::from_rng(&mut *self.rng_write_lock());
        let dealing = clib_create_dealing(
            algorithm_id,
            context_data,
            dealer_index,
            reconstruction_threshold,
            receiver_keys,
            &shares,
            seed,
        )
        .map_err(|e| IDkgCreateDealingVaultError::InternalError(format!("{e:?}")))?;
        let bytes = dealing
            .serialize()
            .map_err(|e| IDkgCreateDealingVaultError::SerializationError(format!("{e:?}")))?;
        Ok(IDkgDealingInternalBytes::from(bytes))
    }

    fn idkg_verify_dealing_private_internal(
        &self,
        algorithm_id: AlgorithmId,
        dealing: &IDkgDealingInternal,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        let (receiver_public_key, receiver_secret_key) =
            self.mega_keyset_from_sks(&receiver_key_id)?;

        Ok(privately_verify_dealing(
            algorithm_id,
            dealing,
            &receiver_secret_key,
            &receiver_public_key,
            context_data,
            dealer_index,
            receiver_index,
        )?)
    }

    fn idkg_load_transcript_internal(
        &self,
        alg: AlgorithmId,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        if self
            .commitment_opening_from_sks(transcript.combined_commitment.commitment())
            .is_ok()
        {
            // If secret share has already been stored in the C-SKS, nothing to do
            Ok(BTreeMap::new())
        } else {
            let (public_key, private_key) = self.mega_keyset_from_sks(key_id)?;

            let compute_secret_shares_result = compute_secret_shares(
                alg,
                dealings,
                transcript,
                context_data,
                receiver_index,
                &private_key,
                &public_key,
            );

            match compute_secret_shares_result {
                Ok(opening) => {
                    let opening_bytes =
                        CommitmentOpeningBytes::try_from(&opening).map_err(|e| {
                            IDkgLoadTranscriptError::SerializationError {
                                internal_error: format!("{e:?}"),
                            }
                        })?;
                    match self.canister_sks_write_lock().insert_or_replace(
                        KeyId::from(transcript.combined_commitment.commitment()),
                        CspSecretKey::IDkgCommitmentOpening(opening_bytes),
                        Some(IDKG_THRESHOLD_KEYS_SCOPE),
                    ) {
                        Ok(_) => Ok(BTreeMap::new()),
                        Err(SecretKeyStoreWriteError::SerializationError(e)) => {
                            Err(IDkgLoadTranscriptError::InternalError { internal_error: e })
                        }
                        Err(SecretKeyStoreWriteError::TransientError(e)) => {
                            Err(IDkgLoadTranscriptError::TransientInternalError {
                                internal_error: e,
                            })
                        }
                    }
                }
                Err(IDkgComputeSecretSharesInternalError::ComplaintShouldBeIssued) => {
                    let seed = Seed::from_rng(&mut *self.rng_write_lock());
                    let complaints = generate_complaints(
                        alg,
                        dealings,
                        context_data,
                        receiver_index,
                        &private_key,
                        &public_key,
                        seed,
                    )?;
                    Ok(complaints)
                }
                Err(IDkgComputeSecretSharesInternalError::InvalidCiphertext(_))
                | Err(IDkgComputeSecretSharesInternalError::UnsupportedAlgorithm)
                | Err(IDkgComputeSecretSharesInternalError::UnableToReconstruct(_))
                | Err(IDkgComputeSecretSharesInternalError::UnableToCombineOpenings(_)) => {
                    Err(IDkgLoadTranscriptError::InvalidArguments {
                        internal_error: format!("{compute_secret_shares_result:?}"),
                    })
                }
            }
        }
    }

    fn idkg_load_transcript_with_openings_internal(
        &self,
        alg: AlgorithmId,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<(), IDkgLoadTranscriptError> {
        if self
            .commitment_opening_from_sks(transcript.combined_commitment.commitment())
            .is_ok()
        {
            // If secret share has already been stored in the C-SKS, nothing to do
            Ok(())
        } else {
            let (public_key, private_key) = self.mega_keyset_from_sks(key_id)?;
            let compute_secret_shares_with_openings_result = compute_secret_shares_with_openings(
                alg,
                dealings,
                openings,
                transcript,
                context_data,
                receiver_index,
                &private_key,
                &public_key,
            );
            match compute_secret_shares_with_openings_result {
                Ok(opening) => {
                    let opening_bytes =
                        CommitmentOpeningBytes::try_from(&opening).map_err(|e| {
                            IDkgLoadTranscriptError::SerializationError {
                                internal_error: format!("{e:?}"),
                            }
                        })?;
                    self.canister_sks_write_lock()
                        .insert_or_replace(
                            KeyId::from(transcript.combined_commitment.commitment()),
                            CspSecretKey::IDkgCommitmentOpening(opening_bytes),
                            Some(IDKG_THRESHOLD_KEYS_SCOPE),
                        )
                        .map_err(|e| match e {
                            SecretKeyStoreWriteError::SerializationError(e) => {
                                IDkgLoadTranscriptError::InternalError { internal_error: e }
                            }
                            SecretKeyStoreWriteError::TransientError(e) => {
                                IDkgLoadTranscriptError::TransientInternalError {
                                    internal_error: e,
                                }
                            }
                        })?;
                    Ok(())
                }
                Err(IDkgComputeSecretSharesWithOpeningsInternalError::ComplaintShouldBeIssued) => {
                    Err(IDkgLoadTranscriptError::InvalidArguments {
                        internal_error: "An invalid dealing with no openings was provided"
                            .to_string(),
                    })
                }
                Err(
                    e
                    @ IDkgComputeSecretSharesWithOpeningsInternalError::InsufficientOpenings(_, _),
                ) => Err(IDkgLoadTranscriptError::InsufficientOpenings {
                    internal_error: format!("{e:?}"),
                }),
                Err(e @ IDkgComputeSecretSharesWithOpeningsInternalError::InvalidCiphertext(_))
                | Err(e @ IDkgComputeSecretSharesWithOpeningsInternalError::UnsupportedAlgorithm)
                | Err(
                    e @ IDkgComputeSecretSharesWithOpeningsInternalError::UnableToReconstruct(_),
                )
                | Err(
                    e
                    @ IDkgComputeSecretSharesWithOpeningsInternalError::UnableToCombineOpenings(_),
                ) => Err(IDkgLoadTranscriptError::InvalidArguments {
                    internal_error: format!("{e:?}"),
                }),
            }
        }
    }

    fn idkg_gen_dealing_encryption_key_pair_internal(
        &self,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        let seed = self.generate_seed();
        let (public_key, csp_secret_key, key_id) = generate_idkg_key_material_from_seed(seed)?;
        let mut public_key_proto = idkg_dealing_encryption_pk_to_proto(public_key.clone());
        self.set_timestamp(&mut public_key_proto);
        let valid_public_key = validate_idkg_dealing_encryption_public_key(public_key_proto)?;
        self.idkg_store_secret_and_public_keys(
            key_id,
            csp_secret_key,
            valid_public_key.get().clone(),
        )?;
        Ok(public_key)
    }

    fn idkg_store_secret_and_public_keys(
        &self,
        key_id: KeyId,
        csp_secret_key: CspSecretKey,
        public_key_proto: PublicKey,
    ) -> Result<(), CspCreateMEGaKeyError> {
        let (mut sks_write_lock, mut pks_write_lock) = self.sks_and_pks_write_locks();
        sks_write_lock
            .insert(key_id, csp_secret_key, Some(IDKG_MEGA_SCOPE))
            .map_err(|sks_error| match sks_error {
                SecretKeyStoreInsertionError::DuplicateKeyId(key_id) => {
                    CspCreateMEGaKeyError::DuplicateKeyId { key_id }
                }
                SecretKeyStoreInsertionError::TransientError(e) => {
                    CspCreateMEGaKeyError::TransientInternalError {
                        internal_error: format!(
                            "Secret key store persistence I/O error while creating MEGa keys: {e}"
                        ),
                    }
                }
                SecretKeyStoreInsertionError::SerializationError(e) => CspCreateMEGaKeyError::InternalError {
                    internal_error: format!(
                        "Secret key store persistence serialization error while creating MEGa keys: {e}"
                    ),
                },
            })
            .and_then(|()| {
                pks_write_lock
                    .add_idkg_dealing_encryption_pubkey(public_key_proto)
                    .map_err(|err| match err {
                        PublicKeyAddError::Io(_) => CspCreateMEGaKeyError::TransientInternalError {
                            internal_error: format!(
                                "failed to add iDKG dealing encryption public key: {err:?}"
                            ),
                        },
                    })
            })
    }

    fn idkg_open_dealing_internal(
        &self,
        alg: AlgorithmId,
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: &[u8],
        opener_index: NodeIndex,
        opener_key_id: &KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
        let (opener_public_key, opener_private_key) = self
            .mega_keyset_from_sks(opener_key_id)
            .map_err(|e| match e {
                MEGaKeysetFromSksError::PrivateKeyNotFound => {
                    IDkgOpenTranscriptError::PrivateKeyNotFound {
                        key_id: opener_key_id.to_string(),
                    }
                }
                deser_err @ MEGaKeysetFromSksError::DeserializationError(_) => {
                    IDkgOpenTranscriptError::InternalError {
                        internal_error: format!("{deser_err:?}"),
                    }
                }
            })?;
        open_dealing(
            alg,
            &dealing,
            context_data,
            dealer_index,
            opener_index,
            &opener_private_key,
            &opener_public_key,
        )
        .map_err(|e| IDkgOpenTranscriptError::InternalError {
            internal_error: format!("{e:?}"),
        })
    }

    fn idkg_retain_active_keys_internal(
        &self,
        active_canister_key_ids: BTreeSet<KeyId>,
        oldest_public_key: MEGaPublicKey,
    ) -> Result<(), IDkgRetainKeysError> {
        let oldest_public_key_proto = idkg_dealing_encryption_pk_to_proto(oldest_public_key);
        // First check, while only holding a read lock on the PKS, if a call to
        // [`idkg_retain_active_dealing_encryption_public_keys`] would modify the public key store.
        // The reasons for doing this while holding a read lock (and, if necessary, thereafter
        // separately acquiring write locks for both the secret and public key stores) are:
        //  - [`IDkgProtocolCspVault::idkg_retain_active_keys`] is called by consensus around once
        //    per minute, but we expect to actually have to delete old iDKG dealing encryption keys
        //    only at much longer time intervals (on the order of hours/days; configured in the
        //    registry) on production subnets using canister threshold
        //    signatures such as tECDSA or tSchnorr.
        //  - Acquiring both PKS and SKS write locks each time blocks all readers - analysis shows
        //    that they sometimes end up waiting for up to 1 second.
        // The drawback of this approach is that it introduces a race condition - between the time
        // that the PKS read lock is released, and the PKS and SKS write locks are acquired, the
        // key stores could have been modified by another writer. However, this is the lesser of two
        // evils, since:
        //  - We only expect the set of iDKG dealing encryption keys to be modified as part of key
        //    rotation, which doesn't happen that often.
        //  - Even if the key stores are modified by another writer, the worst that can happen is
        //    that we perform unnecessary work, i.e., check the iDKG dealing encryption keys in the
        //    PKS again, and determine that there is no need to delete any key(s). This operation is
        //    quite cheap, since we don't expect there to be more than a handful of keys at any
        //    point in time (most likely just 1-2).
        let would_pks_be_modified = {
            let pks_read_lock = self.public_key_store_read_lock();
            would_idkg_retain_modify_public_key_store(&pks_read_lock, &oldest_public_key_proto)?
        }; // drop read lock on pks

        // If the previous check determined that the public key store would be modified, acquire
        // write locks for both PKS and SKS and try to actually make the modifications.
        if would_pks_be_modified {
            let (sks_write_lock, mut pks_write_lock) = self.sks_and_pks_write_locks();
            let is_pks_modified = idkg_retain_active_dealing_encryption_public_keys(
                &mut pks_write_lock,
                &oldest_public_key_proto,
            )?;
            if is_pks_modified {
                let key_ids_to_keep = idkg_public_key_proto_to_key_id(
                    &pks_write_lock.idkg_dealing_encryption_pubkeys(),
                )?;
                idkg_retain_active_dealing_encryption_secret_keys(sks_write_lock, key_ids_to_keep)?;
            }
        } //drop locks on sks and pks
        self.idkg_retain_active_canister_secret_shares(active_canister_key_ids)
    }

    fn idkg_retain_active_canister_secret_shares(
        &self,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), IDkgRetainKeysError> {
        let filter = move |key_id: &KeyId, _: &CspSecretKey| active_key_ids.contains(key_id);
        if self
            .canister_sks_read_lock()
            .retain_would_modify_keystore(filter.clone(), IDKG_THRESHOLD_KEYS_SCOPE)
        {
            // The fact that we perform the initial check holding a read lock on the canister SKS,
            // and then possibly acquire a write lock to actually modify the canister SKS, results
            // in a potential race condition here. This has two consequences:
            //  - In case another writer managed to get the write lock after we released the read
            //    lock and acquired the write lock, and also executed the retain operation with the
            //    same set of `active_key_ids`, this is fine, since the operation is idempotent.
            //  - Another potential issue is that a new transcript could have been loaded, and a
            //    new key added, between the time that retain on the crypto component was called,
            //    and the time that we actually call retain here. In this case, a newly-created key
            //    may be deleted. This is currently not an issue given how the crypto component is
            //    called from consensus, but an approach similar to the one proposed for NI-DKG in
            //    CRP-1094 (adding the registry version to the keys) could be applied here also.
            self.canister_sks_write_lock()
                .retain(
                    filter,
                    IDKG_THRESHOLD_KEYS_SCOPE,
                )
                .map_err(|e| match e {
                    SecretKeyStoreWriteError::SerializationError(e) => {
                        IDkgRetainKeysError::SerializationError {
                            internal_error: format!("Serialization error while retaining active IDKG canister secret shares: {e:?}"),
                        }

                    }
                    SecretKeyStoreWriteError::TransientError(e) => {
                        IDkgRetainKeysError::TransientInternalError {
                            internal_error: format!("IO error while retaining active IDKG canister secret shares: {e:?}")
                        }

                    }
                })
        } else {
            Ok(())
        }
    }

    fn get_secret_shares(
        &self,
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<SecretShares, IDkgCreateDealingVaultError> {
        match transcript_operation {
            IDkgTranscriptOperationInternal::Random => Ok(SecretShares::Random),
            IDkgTranscriptOperationInternal::RandomUnmasked => Ok(SecretShares::RandomUnmasked),
            IDkgTranscriptOperationInternal::ReshareOfUnmasked(commitment)
            | IDkgTranscriptOperationInternal::ReshareOfMasked(commitment) => {
                let secret_share_bytes = self.commitment_opening_from_sks(commitment)?;
                SecretShares::try_from((&secret_share_bytes, None))
                    .map_err(|e| IDkgCreateDealingVaultError::InternalError(format!("{e:?}")))
            }
            IDkgTranscriptOperationInternal::UnmaskedTimesMasked(commitment_1, commitment_2) => {
                let unmasked_share_bytes = self.commitment_opening_from_sks(commitment_1)?;
                let masked_share_bytes = self.commitment_opening_from_sks(commitment_2)?;
                SecretShares::try_from((&unmasked_share_bytes, Some(&masked_share_bytes)))
                    .map_err(|e| IDkgCreateDealingVaultError::InternalError(format!("{e:?}")))
            }
        }
    }

    fn commitment_opening_from_sks(
        &self,
        commitment: &PolynomialCommitment,
    ) -> Result<CommitmentOpeningBytes, IDkgCreateDealingVaultError> {
        let key_id = KeyId::from(commitment);
        let opening = self.canister_sks_read_lock().get(&key_id);
        match &opening {
            Some(CspSecretKey::IDkgCommitmentOpening(bytes)) => Ok(bytes.clone()),
            _ => Err(IDkgCreateDealingVaultError::SecretSharesNotFound {
                commitment_string: format!("{commitment:?}"),
            }),
        }
    }

    fn mega_keyset_from_sks(
        &self,
        key_id: &KeyId,
    ) -> Result<(MEGaPublicKey, MEGaPrivateKey), MEGaKeysetFromSksError> {
        type Mkfse = MEGaKeysetFromSksError;
        let key = self.sks_read_lock().get(key_id);
        // Obtaining the lock in the `match` would hold it longer than necessary
        match &key {
            Some(CspSecretKey::MEGaEncryptionK256(keyset_bytes)) => {
                let public_key = MEGaPublicKey::try_from(&keyset_bytes.public_key)
                    .map_err(|e| Mkfse::DeserializationError(format!("{e:?}")))?;
                let private_key = MEGaPrivateKey::try_from(&keyset_bytes.private_key)
                    .map_err(|e| Mkfse::DeserializationError(format!("{e:?}")))?;
                Ok((public_key, private_key))
            }
            Some(_non_mega_encryption_k256_key) => Err(Mkfse::DeserializationError(format!(
                "secret key with ID {key_id} is not a MEGa encryption key set"
            ))),
            None => Err(Mkfse::PrivateKeyNotFound),
        }
    }
}

#[derive(Debug)]
enum MEGaKeysetFromSksError {
    DeserializationError(String),
    PrivateKeyNotFound,
}

impl From<MEGaKeysetFromSksError> for IDkgVerifyDealingPrivateError {
    fn from(mega_keyset_from_sks_error: MEGaKeysetFromSksError) -> Self {
        type Mkfse = MEGaKeysetFromSksError;
        type Ivdpe = IDkgVerifyDealingPrivateError;
        match mega_keyset_from_sks_error {
            Mkfse::DeserializationError(e) => Ivdpe::InternalError(e),
            Mkfse::PrivateKeyNotFound => Ivdpe::PrivateKeyNotFound,
        }
    }
}

impl From<MEGaKeysetFromSksError> for IDkgLoadTranscriptError {
    fn from(mega_keyset_from_sks_error: MEGaKeysetFromSksError) -> Self {
        type Mkfse = MEGaKeysetFromSksError;
        type Ilte = IDkgLoadTranscriptError;
        match mega_keyset_from_sks_error {
            Mkfse::DeserializationError(e) => Ilte::SerializationError { internal_error: e },
            Mkfse::PrivateKeyNotFound => Ilte::PrivateKeyNotFound,
        }
    }
}

fn generate_idkg_key_material_from_seed(
    seed: Seed,
) -> Result<(MEGaPublicKey, CspSecretKey, KeyId), CspCreateMEGaKeyError> {
    let (public_key, private_key) = gen_keypair(EccCurveType::K256, seed);

    let key_id =
        KeyId::try_from(&public_key).map_err(|e| CspCreateMEGaKeyError::InternalError {
            internal_error: format!(
                "Failed to create key ID from MEGa public key {:?}: {e}",
                &public_key
            ),
        })?;
    let csp_secret_key = CspSecretKey::MEGaEncryptionK256(MEGaKeySetK256Bytes {
        public_key: MEGaPublicKeyK256Bytes::try_from(&public_key)
            .map_err(CspCreateMEGaKeyError::SerializationError)?,
        private_key: MEGaPrivateKeyK256Bytes::try_from(&private_key)
            .map_err(CspCreateMEGaKeyError::SerializationError)?,
    });
    Ok((public_key, csp_secret_key, key_id))
}

fn idkg_public_key_proto_to_key_id(
    public_keys: &[PublicKey],
) -> Result<BTreeSet<KeyId>, IDkgRetainKeysError> {
    public_keys
        .iter()
        .map(|public_key| {
            let curve_type = match AlgorithmIdProto::try_from(public_key.algorithm).ok() {
                Some(AlgorithmIdProto::MegaSecp256k1) => Ok(EccCurveType::K256),
                alg_id => Err(IDkgRetainKeysError::InternalError {
                    internal_error: format!("Unsupported algorithm {alg_id:?}"),
                }),
            }?;

            let mega_public_key = MEGaPublicKey::deserialize(curve_type, &public_key.key_value)
                .map_err(|err| IDkgRetainKeysError::InternalError {
                    internal_error: format!("Error deserializing IDKG public key: {err:?}"),
                })?;

            KeyId::try_from(&mega_public_key).map_err(|error| IDkgRetainKeysError::InternalError {
                internal_error: format!("Invalid key ID {error:?}"),
            })
        })
        .collect()
}

fn idkg_retain_active_dealing_encryption_secret_keys<S: SecretKeyStore>(
    mut sks_write_lock: RwLockWriteGuard<S>,
    active_secret_key_ids: BTreeSet<KeyId>,
) -> Result<(), IDkgRetainKeysError> {
    sks_write_lock
        .retain(
            move |key_id, _| active_secret_key_ids.contains(key_id),
            IDKG_MEGA_SCOPE,
        )
        .map_err(|sks_error| match sks_error {
            SecretKeyStoreWriteError::SerializationError(e) => {
                IDkgRetainKeysError::SerializationError {
                    internal_error: format!("Serialization error while retaining active IDKG dealing encryption secret keys: {e:?}"),
                }
            }
            SecretKeyStoreWriteError::TransientError(e) => {
                IDkgRetainKeysError::TransientInternalError {
                    internal_error: format!("IO error while retaining active IDKG dealing encryption secret keys: {e:?}")
                }
            }
        })
}

fn idkg_retain_active_dealing_encryption_public_keys<P: PublicKeyStore>(
    pks_write_lock: &mut RwLockWriteGuard<P>,
    oldest_public_key: &PublicKey,
) -> Result<bool, IDkgRetainKeysError> {
    pks_write_lock
        .retain_idkg_public_keys_since(oldest_public_key)
        .map_err(|retain_error| match retain_error {
            PublicKeyRetainError::Io(io_error) => IDkgRetainKeysError::TransientInternalError {
                internal_error: format!(
                    "IO error while retaining active IDKG dealing encryption public keys: {io_error:?}"
                ),
            },
            PublicKeyRetainError::OldestPublicKeyNotFound => IDkgRetainKeysError::InternalError {
                internal_error: format!(
                    "Could not find oldest IDKG public key {:?} locally",
                    &oldest_public_key
                ),
            },
        })
}

fn validate_idkg_dealing_encryption_public_key(
    public_key_proto: PublicKey,
) -> Result<ValidIDkgDealingEncryptionPublicKey, CspCreateMEGaKeyError> {
    ValidIDkgDealingEncryptionPublicKey::try_from(public_key_proto).map_err(|error| {
        CspCreateMEGaKeyError::InternalError {
            internal_error: format!("Key validation error: {error}"),
        }
    })
}

fn would_idkg_retain_modify_public_key_store<P: PublicKeyStore>(
    pks_read_lock: &RwLockReadGuard<P>,
    oldest_public_key: &PublicKey,
) -> Result<bool, IDkgRetainKeysError> {
    pks_read_lock
        .would_retain_idkg_public_keys_modify_pubkey_store(oldest_public_key)
        .map_err(|retain_error| match retain_error {
            PublicKeyRetainCheckError::OldestPublicKeyNotFound => {
                IDkgRetainKeysError::InternalError {
                    internal_error: format!(
                        "Could not find oldest IDKG public key {:?} locally",
                        &oldest_public_key
                    ),
                }
            }
        })
}

fn idkg_internal_dealings_from_verified_dealings(
    verified_dealings: &BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
) -> Result<BTreeMap<NodeIndex, IDkgDealingInternal>, IDkgLoadTranscriptError> {
    verified_dealings
        .iter()
        .map(|(index, signed_dealing)| {
            let dealing = IDkgDealingInternal::try_from(signed_dealing).map_err(|e| {
                IDkgLoadTranscriptError::SerializationError {
                    internal_error: format!("failed to deserialize internal dealing: {e:?}"),
                }
            })?;
            Ok((*index, dealing))
        })
        .collect()
}

fn idkg_internal_dealings_from_bytes(
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternalBytes>,
) -> Result<BTreeMap<NodeIndex, IDkgDealingInternal>, IDkgLoadTranscriptError> {
    verified_dealings
        .iter()
        .map(|(index, signed_dealing)| {
            let dealing =
                IDkgDealingInternal::deserialize(signed_dealing.as_ref()).map_err(|e| {
                    IDkgLoadTranscriptError::SerializationError {
                        internal_error: format!("failed to deserialize internal dealing: {e:?}"),
                    }
                })?;
            Ok((*index, dealing))
        })
        .collect()
}
