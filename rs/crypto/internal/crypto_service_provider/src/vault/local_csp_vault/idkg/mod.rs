use crate::api::CspCreateMEGaKeyError;
use crate::canister_threshold::{IDKG_MEGA_SCOPE, IDKG_THRESHOLD_KEYS_SCOPE};
use crate::key_id::KeyId;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::{SecretKeyStore, SecretKeyStorePersistenceError};
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
use ic_logger::debug;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError,
    IDkgRetainThresholdKeysError, IDkgVerifyDealingPrivateError,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeIndex, NumberOfNodes};
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
            MetricsDomain::IDkgProtocol,
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
            MetricsDomain::IDkgProtocol,
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
            MetricsDomain::IDkgProtocol,
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
            MetricsDomain::IDkgProtocol,
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

        let (public_key, private_key) = self.idkg_gen_mega_key_pair_internal()?;
        let result = self
            .idkg_add_private_key_to_secret_key_store(&public_key, private_key)
            .and_then(|()| self.idkg_add_public_key_to_public_key_store(public_key.clone()))
            .map(|()| public_key);

        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
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
            MetricsDomain::IDkgProtocol,
            MetricsScope::Local,
            "idkg_open_dealing",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }

    //TODO CRP-1729: use `oldest_public_key` to retain active public keys and corresponding private keys.
    fn idkg_retain_active_keys(
        &self,
        active_key_ids: BTreeSet<KeyId>,
        _oldest_public_key: MEGaPublicKey,
    ) -> Result<(), IDkgRetainThresholdKeysError> {
        debug!(self.logger; crypto.method_name => "idkg_retain_active_keys");
        let start_time = self.metrics.now();
        self.canister_sks_write_lock()
            .retain(
                move |key_id, _| active_key_ids.contains(key_id),
                IDKG_THRESHOLD_KEYS_SCOPE,
            )
            .map_err(|e| match e {
                SecretKeyStorePersistenceError::SerializationError(e) => {
                    IDkgRetainThresholdKeysError::InternalError { internal_error: e }
                }
                SecretKeyStorePersistenceError::IoError(e) => {
                    IDkgRetainThresholdKeysError::TransientInternalError { internal_error: e }
                }
            })?;
        self.metrics.observe_duration_seconds(
            MetricsDomain::IDkgProtocol,
            MetricsScope::Local,
            "idkg_retain_active_keys",
            MetricsResult::Ok,
            start_time,
        );
        Ok(())
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
                        Err(SecretKeyStorePersistenceError::SerializationError(e)) => {
                            Err(IDkgLoadTranscriptError::InternalError { internal_error: e })
                        }
                        Err(SecretKeyStorePersistenceError::IoError(e)) => {
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
        let result = if self
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
                            SecretKeyStorePersistenceError::SerializationError(e) => {
                                IDkgLoadTranscriptError::InternalError { internal_error: e }
                            }
                            SecretKeyStorePersistenceError::IoError(e) => {
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
        };
        result
    }

    fn idkg_gen_mega_key_pair_internal(
        &self,
    ) -> Result<(MEGaPublicKey, MEGaPrivateKey), CspCreateMEGaKeyError> {
        let seed = Seed::from_rng(&mut *self.rng_write_lock());

        gen_keypair(EccCurveType::K256, seed).map_err(CspCreateMEGaKeyError::FailedKeyGeneration)
    }

    fn idkg_add_private_key_to_secret_key_store(
        &self,
        public_key: &MEGaPublicKey,
        private_key: MEGaPrivateKey,
    ) -> Result<(), CspCreateMEGaKeyError> {
        let key_id =
            KeyId::try_from(public_key).map_err(|e| CspCreateMEGaKeyError::InternalError {
                internal_error: format!(
                    "Failed to create key ID from MEGa public key {:?}: {}",
                    public_key, e
                ),
            })?;
        let public_key_bytes = MEGaPublicKeyK256Bytes::try_from(public_key)
            .map_err(CspCreateMEGaKeyError::SerializationError)?;
        let private_key_bytes = MEGaPrivateKeyK256Bytes::try_from(&private_key)
            .map_err(CspCreateMEGaKeyError::SerializationError)?;
        self.store_secret_key(
            key_id,
            CspSecretKey::MEGaEncryptionK256(MEGaKeySetK256Bytes {
                public_key: public_key_bytes,
                private_key: private_key_bytes,
            }),
            Some(IDKG_MEGA_SCOPE),
        )
        .map_err(|err| CspCreateMEGaKeyError::from(err))
    }

    fn idkg_add_public_key_to_public_key_store(
        &self,
        public_key: MEGaPublicKey,
    ) -> Result<(), CspCreateMEGaKeyError> {
        let mut existing_public_keys = self
            .public_key_store_read_lock()
            .idkg_dealing_encryption_pubkeys()
            .clone();
        existing_public_keys.push(crate::keygen::utils::idkg_dealing_encryption_pk_to_proto(
            public_key,
        ));
        self.public_key_store_write_lock()
            .set_idkg_dealing_encryption_pubkeys(existing_public_keys)
            .map_err(|err| CspCreateMEGaKeyError::TransientInternalError {
                internal_error: format!("IO error: {:?}", err),
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
