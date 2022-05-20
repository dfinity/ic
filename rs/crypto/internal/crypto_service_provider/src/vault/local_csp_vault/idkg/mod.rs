use crate::api::CspCreateMEGaKeyError;
use crate::canister_threshold::IDKG_THRESHOLD_KEYS_SCOPE;
use crate::keygen::mega_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSecretKey;
use crate::vault::api::IDkgProtocolCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_threshold_sig_ecdsa::{
    compute_secret_shares, compute_secret_shares_with_openings,
    create_dealing as tecdsa_create_dealing, gen_keypair, generate_complaints, open_dealing,
    privately_verify_dealing, CommitmentOpening, CommitmentOpeningBytes, EccCurveType,
    IDkgComplaintInternal, IDkgComputeSecretSharesInternalError, IDkgDealingInternal,
    IDkgTranscriptInternal, IDkgTranscriptOperationInternal, MEGaKeySetK256Bytes, MEGaPrivateKey,
    MEGaPrivateKeyK256Bytes, MEGaPublicKey, MEGaPublicKeyK256Bytes, PolynomialCommitment,
    SecretShares, Seed,
};
use ic_crypto_sha::{DomainSeparationContext, Sha256};
use ic_logger::debug;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError,
    IDkgVerifyDealingPrivateError,
};
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;
use std::convert::TryFrom;

const COMMITMENT_KEY_ID_DOMAIN: &str = "ic-key-id-idkg-commitment";

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> IDkgProtocolCspVault
    for LocalCspVault<R, S, C>
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

        let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());

        let tecdsa_shares = self.get_secret_shares(transcript_operation)?;

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

    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        // If secret share has already been stored in the C-SKS, nothing to do
        if self
            .commitment_opening_from_sks(transcript.combined_commitment.commitment())
            .is_ok()
        {
            return Ok(BTreeMap::new());
        }

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
                let opening_bytes = CommitmentOpeningBytes::try_from(&opening).map_err(|e| {
                    IDkgLoadTranscriptError::SerializationError {
                        internal_error: format!("{:?}", e),
                    }
                })?;
                self.canister_sks_write_lock().insert_or_replace(
                    commitment_key_id(transcript.combined_commitment.commitment()),
                    CspSecretKey::IDkgCommitmentOpening(opening_bytes),
                    Some(IDKG_THRESHOLD_KEYS_SCOPE),
                );
                Ok(BTreeMap::new())
            }
            Err(IDkgComputeSecretSharesInternalError::InconsistentCommitments) => {
                let randomness = Randomness::from(self.csprng.write().gen::<[u8; 32]>());
                let complaints = generate_complaints(
                    dealings,
                    context_data,
                    receiver_index,
                    &private_key,
                    &public_key,
                    Seed::from_randomness(&randomness),
                )?;
                Ok(complaints)
            }
            Err(IDkgComputeSecretSharesInternalError::InternalError(e)) => {
                Err(IDkgLoadTranscriptError::InternalError {
                    internal_error: format!("{:?}", e),
                })
            }
        }
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
        // If secret share has already been stored in the C-SKS, nothing to do
        if self
            .commitment_opening_from_sks(transcript.combined_commitment.commitment())
            .is_ok()
        {
            return Ok(());
        }

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
                let opening_bytes = CommitmentOpeningBytes::try_from(&opening).map_err(|e| {
                    IDkgLoadTranscriptError::SerializationError {
                        internal_error: format!("{:?}", e),
                    }
                })?;
                self.canister_sks_write_lock().insert_or_replace(
                    commitment_key_id(transcript.combined_commitment.commitment()),
                    CspSecretKey::IDkgCommitmentOpening(opening_bytes),
                    Some(IDKG_THRESHOLD_KEYS_SCOPE),
                );
                Ok(())
            }
            Err(IDkgComputeSecretSharesInternalError::InconsistentCommitments) => {
                Err(IDkgLoadTranscriptError::InvalidArguments {
                    internal_error: "failed to compute secret shares with the provided openings"
                        .to_string(),
                })
            }
            Err(IDkgComputeSecretSharesInternalError::InternalError(e)) => {
                Err(IDkgLoadTranscriptError::InvalidArguments { internal_error: e })
            }
        }
    }

    fn idkg_gen_mega_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        debug!(self.logger; crypto.method_name => "idkg_gen_mega_key_pair");

        let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());

        let (public_key, private_key) = match algorithm_id {
            AlgorithmId::ThresholdEcdsaSecp256k1 => gen_keypair(EccCurveType::K256, seed)
                .map_err(CspCreateMEGaKeyError::FailedKeyGeneration),
            _ => Err(CspCreateMEGaKeyError::UnsupportedAlgorithm { algorithm_id }),
        }?;

        let public_key_bytes = MEGaPublicKeyK256Bytes::try_from(&public_key)
            .map_err(CspCreateMEGaKeyError::SerializationError)?;
        let private_key_bytes = MEGaPrivateKeyK256Bytes::try_from(&private_key)
            .map_err(CspCreateMEGaKeyError::SerializationError)?;

        self.store_secret_key_or_panic(
            CspSecretKey::MEGaEncryptionK256(MEGaKeySetK256Bytes {
                public_key: public_key_bytes,
                private_key: private_key_bytes,
            }),
            mega_key_id(&public_key),
        );

        Ok(public_key)
    }

    fn idkg_open_dealing(
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
                        key_id: *opener_key_id,
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
}

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore>
    LocalCspVault<R, S, C>
{
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
        let key_id = commitment_key_id(commitment);
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

pub(crate) fn commitment_key_id(commitment: &PolynomialCommitment) -> KeyId {
    let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(
        COMMITMENT_KEY_ID_DOMAIN.to_string(),
    ));
    let commitment_encoding = commitment.to_bytes();
    hash.write(&(commitment_encoding.len() as u64).to_be_bytes());
    hash.write(&commitment_encoding);
    KeyId::from(hash.finish())
}
