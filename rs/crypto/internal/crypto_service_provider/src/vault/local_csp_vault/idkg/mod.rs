use crate::api::CspCreateMEGaKeyError;
use crate::keygen::mega_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSecretKey;
use crate::vault::api::IDkgProtocolCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_sha::{DomainSeparationContext, Sha256};
use ic_logger::debug;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError,
};
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use tecdsa::{
    compute_secret_shares, create_dealing as tecdsa_create_dealing, gen_keypair,
    generate_complaints, CommitmentOpeningBytes, EccCurveType, IDkgComplaintInternal,
    IDkgComputeSecretSharesInternalError, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaKeySetK256Bytes, MEGaPrivateKey, MEGaPrivateKeyK256Bytes,
    MEGaPublicKey, MEGaPublicKeyK256Bytes, PolynomialCommitment, SecretShares, Seed,
};

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
        debug!(self.logger; crypto.method_name => "create_dealing");

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
                self.store_canister_secret_key_or_panic(
                    CspSecretKey::IDkgCommitmentOpening(opening_bytes),
                    commitment_key_id(transcript.combined_commitment.commitment()),
                );
                Ok(BTreeMap::new())
            }
            Err(IDkgComputeSecretSharesInternalError::InconsistentCommitments) => {
                let seed = Seed::from_rng(&mut *self.csprng.write());
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
            Err(IDkgComputeSecretSharesInternalError::InternalError(e)) => {
                Err(IDkgLoadTranscriptError::InternalError {
                    internal_error: format!("{:?}", e),
                })
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
    ) -> Result<(MEGaPublicKey, MEGaPrivateKey), IDkgLoadTranscriptError> {
        match &self.sks_read_lock().get(key_id) {
            Some(CspSecretKey::MEGaEncryptionK256(keyset_bytes)) => {
                let public_key =
                    MEGaPublicKey::try_from(&keyset_bytes.public_key).map_err(|e| {
                        IDkgLoadTranscriptError::SerializationError {
                            internal_error: format!("{:?}", e),
                        }
                    })?;
                let private_key =
                    MEGaPrivateKey::try_from(&keyset_bytes.private_key).map_err(|e| {
                        IDkgLoadTranscriptError::SerializationError {
                            internal_error: format!("{:?}", e),
                        }
                    })?;
                Ok((public_key, private_key))
            }
            _ => Err(IDkgLoadTranscriptError::PrivateKeyNotFound),
        }
    }
}

pub(crate) fn commitment_key_id(commitment: &PolynomialCommitment) -> KeyId {
    let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(
        COMMITMENT_KEY_ID_DOMAIN.to_string(),
    ));
    hash.write(&serde_cbor::to_vec(commitment).expect("Failed to serialize commitment"));
    KeyId::from(hash.finish())
}
