use crate::api::CspCreateMEGaKeyError;
use crate::canister_threshold::{IDKG_MEGA_SCOPE, IDKG_THRESHOLD_KEYS_SCOPE};
use crate::key_id::KeyId;
use crate::keygen::utils::idkg_dealing_encryption_pk_to_proto;
use crate::public_key_store::{PublicKeyAddError, PublicKeyRetainError, PublicKeyStore};
use crate::secret_key_store::{
    SecretKeyStore, SecretKeyStoreInsertionError, SecretKeyStoreWriteError,
};
use crate::types::CspSecretKey;
use crate::vault::api::IDkgProtocolCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_threshold_sig_ecdsa::{
    compute_secret_shares, compute_secret_shares_with_openings,
    create_dealing as tecdsa_create_dealing, gen_keypair, generate_complaints, open_dealing,
    privately_verify_dealing, CommitmentOpening, CommitmentOpeningBytes, EccCurveType,
    IDkgComplaintInternal, IDkgComputeSecretSharesInternalError, IDkgDealingInternal,
    IDkgTranscriptInternal, IDkgTranscriptOperationInternal, MEGaKeySetK256Bytes, MEGaPrivateKey,
    MEGaPrivateKeyK256Bytes, MEGaPublicKey, MEGaPublicKeyK256Bytes, PolynomialCommitment,
    SecretShares, Seed,
};
use ic_crypto_node_key_validation::ValidIDkgDealingEncryptionPublicKey;
use ic_logger::debug;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError, IDkgRetainKeysError,
    IDkgVerifyDealingPrivateError,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeIndex, NumberOfNodes};
use parking_lot::RwLockWriteGuard;
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
        context_data: &[u8],
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: &[MEGaPublicKey],
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError> {
        debug!(self.logger; crypto.method_name => "idkg_create_dealing");
        let start_time = self.metrics.now();
        let result = self.idkg_create_dealing_internal(
            algorithm_id,
            context_data,
            dealer_index,
            reconstruction_threshold,
            receiver_keys,
            transcript_operation,
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
        dealing: &IDkgDealingInternal,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        debug!(self.logger; crypto.method_name => "idkg_verify_dealing_private");
        let start_time = self.metrics.now();
        let result = self.idkg_verify_dealing_private_internal(
            algorithm_id,
            dealing,
            dealer_index,
            receiver_index,
            receiver_key_id,
            context_data,
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
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        let start_time = self.metrics.now();
        let result = self.idkg_load_transcript_internal(
            dealings,
            context_data,
            receiver_index,
            key_id,
            transcript,
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
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<(), IDkgLoadTranscriptError> {
        let start_time = self.metrics.now();
        let result = self.idkg_load_transcript_with_openings_internal(
            dealings,
            openings,
            context_data,
            receiver_index,
            key_id,
            transcript,
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
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: &[u8],
        opener_index: NodeIndex,
        opener_key_id: &KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
        let start_time = self.metrics.now();
        let result = self.idkg_open_dealing_internal(
            dealing,
            dealer_index,
            context_data,
            opener_index,
            opener_key_id,
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
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError> {
        let tecdsa_shares = self.get_secret_shares(transcript_operation)?;

        let seed = Seed::from_rng(&mut *self.rng_write_lock());
        tecdsa_create_dealing(
            algorithm_id,
            context_data,
            dealer_index,
            reconstruction_threshold,
            receiver_keys,
            &tecdsa_shares,
            seed,
        )
        .map_err(|e| IDkgCreateDealingError::InternalError {
            internal_error: format!("{:?}", e),
        })
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
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        let result = if self
            .commitment_opening_from_sks(transcript.combined_commitment.commitment())
            .is_ok()
        {
            // If secret share has already been stored in the C-SKS, nothing to do
            Ok(BTreeMap::new())
        } else {
            let (public_key, private_key) = self.mega_keyset_from_sks(key_id)?;

            let compute_secret_shares_result = compute_secret_shares(
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
                                internal_error: format!("{:?}", e),
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
                        dealings,
                        context_data,
                        receiver_index,
                        &private_key,
                        &public_key,
                        seed,
                    )?;
                    Ok(complaints)
                }
                Err(IDkgComputeSecretSharesInternalError::InsufficientOpenings(_, _)) => {
                    Err(IDkgLoadTranscriptError::InsufficientOpenings {
                        internal_error: format!("{:?}", compute_secret_shares_result),
                    })
                }
                Err(IDkgComputeSecretSharesInternalError::InvalidCiphertext(_))
                | Err(IDkgComputeSecretSharesInternalError::UnableToReconstruct(_))
                | Err(IDkgComputeSecretSharesInternalError::UnableToCombineOpenings(_)) => {
                    Err(IDkgLoadTranscriptError::InvalidArguments {
                        internal_error: format!("{:?}", compute_secret_shares_result),
                    })
                }
            }
        };
        result
    }

    fn idkg_load_transcript_with_openings_internal(
        &self,
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
                                internal_error: format!("{:?}", e),
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
                Err(IDkgComputeSecretSharesInternalError::ComplaintShouldBeIssued) => {
                    Err(IDkgLoadTranscriptError::InvalidArguments {
                        internal_error: "An invalid dealing with no openings was provided"
                            .to_string(),
                    })
                }
                Err(IDkgComputeSecretSharesInternalError::InsufficientOpenings(_, _)) => {
                    Err(IDkgLoadTranscriptError::InsufficientOpenings {
                        internal_error: format!("{:?}", compute_secret_shares_with_openings_result),
                    })
                }
                Err(IDkgComputeSecretSharesInternalError::InvalidCiphertext(_))
                | Err(IDkgComputeSecretSharesInternalError::UnableToReconstruct(_))
                | Err(IDkgComputeSecretSharesInternalError::UnableToCombineOpenings(_)) => {
                    Err(IDkgLoadTranscriptError::InvalidArguments {
                        internal_error: format!("{:?}", compute_secret_shares_with_openings_result),
                    })
                }
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
                            "Secret key store persistence I/O error while creating MEGa keys: {}",
                            e
                        ),
                    }
                }
                SecretKeyStoreInsertionError::SerializationError(e) => CspCreateMEGaKeyError::InternalError {
                    internal_error: format!(
                        "Secret key store persistence serialization error while creating MEGa keys: {}",
                        e
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
                _ => IDkgOpenTranscriptError::InternalError {
                    internal_error: format!("{:?}", e),
                },
            })?;
        open_dealing(
            &dealing,
            context_data,
            dealer_index,
            opener_index,
            &opener_private_key,
            &opener_public_key,
        )
        .map_err(|e| IDkgOpenTranscriptError::InternalError {
            internal_error: format!("{:?}", e),
        })
    }

    fn idkg_retain_active_keys_internal(
        &self,
        active_canister_key_ids: BTreeSet<KeyId>,
        oldest_public_key: MEGaPublicKey,
    ) -> Result<(), IDkgRetainKeysError> {
        let oldest_public_key_proto = idkg_dealing_encryption_pk_to_proto(oldest_public_key);
        {
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
        self.canister_sks_write_lock()
            .retain(
                move |key_id, _| active_key_ids.contains(key_id),
                IDKG_THRESHOLD_KEYS_SCOPE,
            )
            .map_err(|e| match e {
                SecretKeyStoreWriteError::SerializationError(e) => {
                    IDkgRetainKeysError::SerializationError {
                        internal_error: format!("Serialization error while retaining active IDKG canister secret shares: {:?}", e),
                    }

                }
                SecretKeyStoreWriteError::TransientError(e) => {
                    IDkgRetainKeysError::TransientInternalError {
                        internal_error: format!("IO error while retaining active IDKG canister secret shares: {:?}", e)
                    }

                }
            })
    }

    fn get_secret_shares(
        &self,
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<SecretShares, IDkgCreateDealingError> {
        match transcript_operation {
            IDkgTranscriptOperationInternal::Random => Ok(SecretShares::Random),
            IDkgTranscriptOperationInternal::ReshareOfUnmasked(commitment)
            | IDkgTranscriptOperationInternal::ReshareOfMasked(commitment) => {
                let secret_share_bytes = self.commitment_opening_from_sks(commitment)?;
                SecretShares::try_from((&secret_share_bytes, None)).map_err(|e| {
                    IDkgCreateDealingError::InternalError {
                        internal_error: format!("{:?}", e),
                    }
                })
            }
            IDkgTranscriptOperationInternal::UnmaskedTimesMasked(commitment_1, commitment_2) => {
                let unmasked_share_bytes = self.commitment_opening_from_sks(commitment_1)?;
                let masked_share_bytes = self.commitment_opening_from_sks(commitment_2)?;
                SecretShares::try_from((&unmasked_share_bytes, Some(&masked_share_bytes))).map_err(
                    |e| IDkgCreateDealingError::InternalError {
                        internal_error: format!("{:?}", e),
                    },
                )
            }
        }
    }

    fn commitment_opening_from_sks(
        &self,
        commitment: &PolynomialCommitment,
    ) -> Result<CommitmentOpeningBytes, IDkgCreateDealingError> {
        let key_id = KeyId::from(commitment);
        let opening = self.canister_sks_read_lock().get(&key_id);
        match &opening {
            Some(CspSecretKey::IDkgCommitmentOpening(bytes)) => Ok(bytes.clone()),
            _ => Err(IDkgCreateDealingError::SecretSharesNotFound {
                commitment_string: format!("{:?}", commitment),
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
                    .map_err(|e| Mkfse::DeserializationError(format!("{:?}", e)))?;
                let private_key = MEGaPrivateKey::try_from(&keyset_bytes.private_key)
                    .map_err(|e| Mkfse::DeserializationError(format!("{:?}", e)))?;
                Ok((public_key, private_key))
            }
            Some(_non_mega_encryption_k256_key) => Err(Mkfse::DeserializationError(format!(
                "secret key with ID {} is not a MEGa encryption key set",
                key_id
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
            let curve_type = match AlgorithmIdProto::from_i32(public_key.algorithm) {
                Some(AlgorithmIdProto::MegaSecp256k1) => Ok(EccCurveType::K256),
                alg_id => Err(IDkgRetainKeysError::InternalError {
                    internal_error: format!("Unsupported algorithm {:?}", alg_id),
                }),
            }?;

            let mega_public_key = MEGaPublicKey::deserialize(curve_type, &public_key.key_value)
                .map_err(|err| IDkgRetainKeysError::InternalError {
                    internal_error: format!("Error deserializing IDKG public key: {:?}", err),
                })?;

            KeyId::try_from(&mega_public_key).map_err(|error| IDkgRetainKeysError::InternalError {
                internal_error: format!("Invalid key ID {:?}", error),
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
                    internal_error: format!("Serialization error while retaining active IDKG dealing encryption secret keys: {:?}", e),
                }
            }
            SecretKeyStoreWriteError::TransientError(e) => {
                IDkgRetainKeysError::TransientInternalError {
                    internal_error: format!("IO error while retaining active IDKG dealing encryption secret keys: {:?}", e)
                }
            }
        })
}

fn idkg_retain_active_dealing_encryption_public_keys<P: PublicKeyStore>(
    pks_write_lock: &mut RwLockWriteGuard<P>,
    oldest_public_key: &PublicKey,
) -> Result<bool, IDkgRetainKeysError> {
    pks_write_lock
        .retain_most_recent_idkg_public_keys_up_to_inclusive(oldest_public_key)
        .map_err(|retain_error| match retain_error {
            PublicKeyRetainError::Io(io_error) => IDkgRetainKeysError::TransientInternalError {
                internal_error: format!(
                    "IO error while retaining active IDKG dealing encryption public keys: {:?}",
                    io_error
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
            internal_error: format!("Key validation error: {}", error),
        }
    })
}
