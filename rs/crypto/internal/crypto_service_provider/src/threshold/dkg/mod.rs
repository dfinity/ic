//! Distributed key generation
//!
//! This file implements the CSP distributed key generation API.  The
//! calculation is done by passing calls through to the crypto lib.  The code
//! here:
//! * Converts the arguments into the type accepted by the crypto lib.
//! * Inserts or retrieves secret keys from the secret key store.

use crate::api::DistributedKeyGenerationCspClient;
use crate::secret_key_store::SecretKeyStore;
use crate::secret_key_store::SecretKeyStoreError;
use crate::types::conversions::dkg_id_to_key_id::dkg_id_to_key_id;
use crate::types::CspPublicCoefficients;
use crate::types::{CspDealing, CspDkgTranscript, CspPop, CspResponse, CspSecretKey};
use crate::Csp;
use dkg::types::{
    CLibResponseBytes, CLibVerifiedResponseBytes, EphemeralKeySetBytes, EphemeralPopBytes,
    EphemeralPublicKeyBytes,
};
use dkg::{
    compute_private_key, create_dealing, create_ephemeral, create_resharing_dealing,
    create_resharing_transcript, create_response, create_transcript, verify_dealing,
    verify_ephemeral, verify_resharing_dealing, verify_response,
};
use ic_crypto_internal_threshold_sig_bls12381 as clib;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1 as dkg;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::{
    CspEncryptionPublicKey, InternalCspEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_sha::{Context, DomainSeparationContext};
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{IDkgId, NodeIndex, NumberOfNodes, Randomness};
use openssl::sha::Sha256;
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

mod conversions;
#[cfg(test)]
mod test_fixtures;
#[cfg(test)]
mod tests;

// TODO(CRP-861): turn this conversion into an Into-trait.
fn csp_enc_pk_and_pop(eph_keyset_bytes: EphemeralKeySetBytes) -> (CspEncryptionPublicKey, CspPop) {
    let internal_pk = InternalCspEncryptionPublicKey::Secp256k1(eph_keyset_bytes.public_key_bytes);
    let public_key = CspEncryptionPublicKey {
        internal: internal_pk,
    };
    let pop = CspPop::Secp256k1(eph_keyset_bytes.pop_bytes);
    (public_key, pop)
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> DistributedKeyGenerationCspClient for Csp<R, S> {
    fn dkg_create_ephemeral(
        &self,
        dkg_id: IDkgId,
        node_id: &[u8],
    ) -> Result<(CspEncryptionPublicKey, CspPop), dkg_errors::DkgCreateEphemeralError> {
        let key_id = dkg_id_to_key_id(&dkg_id);
        let ephemeral_key_set_maybe: Option<EphemeralKeySetBytes> = self
            .get_ephemeral_key(key_id)
            .map_err(dkg_errors::DkgCreateEphemeralError::MalformedSecretKeyError)?;
        if let Some(key_set) = ephemeral_key_set_maybe {
            Ok(csp_enc_pk_and_pop(key_set))
        } else {
            let (secret_key_bytes, public_key_bytes, pop_bytes) =
                create_ephemeral(&mut *self.rng_write_lock(), dkg_id, node_id);
            let key_set = EphemeralKeySetBytes {
                secret_key_bytes,
                public_key_bytes,
                pop_bytes,
            };
            let key_to_store = CspSecretKey::Secp256k1WithPublicKey(key_set);
            match self.sks_write_lock().insert(key_id, key_to_store, None) {
                Ok(()) => Ok(csp_enc_pk_and_pop(key_set)),
                Err(SecretKeyStoreError::DuplicateKeyId(_key_id)) => {
                    let ephemeral_key_set_maybe: Option<EphemeralKeySetBytes> = self
                        .get_ephemeral_key(key_id)
                        .map_err(dkg_errors::DkgCreateEphemeralError::MalformedSecretKeyError)?;
                    if let Some(other_key_set) = ephemeral_key_set_maybe {
                        Ok(csp_enc_pk_and_pop(other_key_set))
                    } else {
                        panic!("Could not insert key but it is not present.");
                    }
                }
            }
        }
    }

    fn dkg_verify_ephemeral(
        &self,
        dkg_id: IDkgId,
        node_id: &[u8],
        key: (CspEncryptionPublicKey, CspPop),
    ) -> Result<(), dkg_errors::DkgVerifyEphemeralError> {
        let (public_key, pop) = key;
        let public_key = conversions::public_key(public_key)
            .map_err(dkg_errors::DkgVerifyEphemeralError::MalformedPublicKeyError)?;
        let pop = conversions::pop(pop)
            .map_err(dkg_errors::DkgVerifyEphemeralError::MalformedPopError)?;
        verify_ephemeral(dkg_id, node_id, (public_key, pop))
    }

    fn dkg_create_dealing(
        &self,
        dkg_id: IDkgId,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, dkg_errors::DkgCreateDealingError> {
        let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());
        let key_id = dkg_id_to_key_id(&dkg_id);
        let ephemeral_key_set: EphemeralKeySetBytes = self
            .get_ephemeral_key(key_id)
            .map_err(dkg_errors::DkgCreateDealingError::MalformedSecretKeyError)?
            .ok_or_else(|| {
                dkg_errors::DkgCreateDealingError::KeyNotFoundError(dkg_errors::KeyNotFoundError {
                    internal_error: format!("No ephemeral key found for dkg {:?}", dkg_id),
                    key_id,
                })
            })?;
        let receiver_keys = &conversions::receiver_keys(receiver_keys)
            .map_err(dkg_errors::DkgCreateDealingError::MalformedPublicKeyError)?;
        create_dealing(
            seed,
            ephemeral_key_set.secret_key_bytes,
            dkg_id,
            threshold,
            receiver_keys,
        )
        .map(CspDealing::from)
    }

    fn dkg_verify_dealing(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        csp_dealing: CspDealing,
    ) -> Result<(), dkg_errors::DkgVerifyDealingError> {
        let receiver_keys = &conversions::receiver_keys(receiver_keys)
            .map_err(dkg_errors::DkgVerifyDealingError::MalformedPublicKeyError)?;

        let dealing = conversions::dealing(&csp_dealing)
            .map_err(dkg_errors::DkgVerifyDealingError::MalformedDealingError)?;

        verify_dealing(threshold, receiver_keys, dealing)
    }

    fn dkg_create_response(
        &self,
        dkg_id: IDkgId,
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        my_index: NodeIndex,
    ) -> Result<CspResponse, dkg_errors::DkgCreateResponseError> {
        let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());

        let key_id = dkg_id_to_key_id(&dkg_id);
        let ephemeral_key_set: EphemeralKeySetBytes = self
            .get_ephemeral_key(key_id)
            .map_err(dkg_errors::DkgCreateResponseError::MalformedSecretKeyError)?
            .ok_or_else(|| {
                dkg_errors::DkgCreateResponseError::KeyNotFoundError(dkg_errors::KeyNotFoundError {
                    internal_error: format!("No ephemeral key found for dkg {:?}", dkg_id),
                    key_id,
                })
            })?;
        let clib_verified_dealings =
            conversions::dealing_map(verified_csp_dealings).map_err(|error| match error {
                conversions::DealingMapConversionError::MalformedPublicKeyError(e) => {
                    dkg_errors::DkgCreateResponseError::MalformedPublicKeyError(e)
                }
                conversions::DealingMapConversionError::MalformedDealingError(e) => {
                    dkg_errors::DkgCreateResponseError::MalformedDealingError(e)
                }
            })?;

        create_response(
            seed,
            &ephemeral_key_set.secret_key_bytes,
            dkg_id,
            &clib_verified_dealings,
            my_index,
        )
        .map(CspResponse::Secp256k1)
    }

    fn dkg_verify_response(
        &self,
        dkg_id: IDkgId,
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        receiver_index: NodeIndex,
        receiver_key: (CspEncryptionPublicKey, CspPop),
        response: CspResponse,
    ) -> Result<(), dkg_errors::DkgVerifyResponseError> {
        let clib_verified_dealings =
            conversions::dealing_map(verified_csp_dealings).map_err(|error| match error {
                conversions::DealingMapConversionError::MalformedPublicKeyError(e) => {
                    dkg_errors::DkgVerifyResponseError::MalformedPublicKeyError(e)
                }
                conversions::DealingMapConversionError::MalformedDealingError(e) => {
                    dkg_errors::DkgVerifyResponseError::MalformedDealingError(e)
                }
            })?;

        let receiver_public_key_bytes = conversions::public_key(receiver_key.0)
            .map_err(dkg_errors::DkgVerifyResponseError::MalformedPublicKeyError)?;
        let clib_response = conversions::response(response)
            .map_err(dkg_errors::DkgVerifyResponseError::MalformedResponseError)?;

        verify_response(
            dkg_id,
            &clib_verified_dealings,
            receiver_index,
            receiver_public_key_bytes,
            &clib_response,
        )
    }

    fn dkg_create_transcript(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        responses: &[Option<CspResponse>],
    ) -> Result<CspDkgTranscript, dkg_errors::DkgCreateTranscriptError> {
        let clib_verified_dealings =
            conversions::dealing_map(verified_csp_dealings).map_err(|error| match error {
                conversions::DealingMapConversionError::MalformedPublicKeyError(e) => {
                    dkg_errors::DkgCreateTranscriptError::MalformedPublicKeyError(e)
                }
                conversions::DealingMapConversionError::MalformedDealingError(e) => {
                    dkg_errors::DkgCreateTranscriptError::MalformedDealingError(e)
                }
            })?;
        let clib_responses: Result<Vec<Option<CLibResponseBytes>>, dkg_errors::MalformedDataError> =
            responses
                .iter()
                .cloned()
                .map(|response_maybe| response_maybe.map(conversions::response).transpose())
                .collect();
        let clib_responses: Vec<Option<CLibResponseBytes>> =
            clib_responses.map_err(dkg_errors::DkgCreateTranscriptError::MalformedResponseError)?;

        let receiver_keys = conversions::receiver_keys(receiver_keys)
            .map_err(dkg_errors::DkgCreateTranscriptError::MalformedPublicKeyError)?;

        let verified_responses: Vec<Option<CLibVerifiedResponseBytes>> =
            pair_responses_with_receivers(clib_responses, &receiver_keys)?;

        create_transcript(threshold, &clib_verified_dealings, &verified_responses)
            .map(CspDkgTranscript::Secp256k1)
    }

    fn dkg_load_private_key(
        &self,
        dkg_id: IDkgId,
        csp_transcript: CspDkgTranscript,
    ) -> Result<(), dkg_errors::DkgLoadPrivateKeyError> {
        let threshold_key_id = {
            let public_coefficients = conversions::transcript_public_coefficients(&csp_transcript);
            public_coefficients_key_id(&public_coefficients)
        };

        if self.sks_read_lock().get(&threshold_key_id).is_some() {
            return Ok(());
        }

        let ephemeral_key_id = dkg_id_to_key_id(&dkg_id);
        let ephemeral_key_set: EphemeralKeySetBytes = self
            .get_ephemeral_key(ephemeral_key_id)
            .map_err(dkg_errors::DkgLoadPrivateKeyError::MalformedSecretKeyError)?
            .ok_or_else(|| {
                dkg_errors::DkgLoadPrivateKeyError::KeyNotFoundError(dkg_errors::KeyNotFoundError {
                    internal_error: format!("No ephemeral key found for dkg {:?}", dkg_id),
                    key_id: ephemeral_key_id,
                })
            })?;

        let transcript = conversions::transcript(csp_transcript)
            .map_err(dkg_errors::DkgLoadPrivateKeyError::MalformedTranscriptError)?;

        if let Some(csp_secret_key) =
            compute_private_key(ephemeral_key_set.secret_key_bytes, &transcript, dkg_id)?
                .map(CspSecretKey::ThresBls12_381)
        {
            // another thread may have inserted the key in the meantime, in which case we
            // skip insertion:
            if !self.sks_read_lock().contains(&threshold_key_id) {
                let mut sks_write_lock = self.sks_write_lock();
                match sks_write_lock.insert(threshold_key_id, csp_secret_key, None) {
                    Ok(()) => {
                        sks_write_lock.remove(&ephemeral_key_id);
                    }
                    Err(SecretKeyStoreError::DuplicateKeyId(_key_id)) => {
                        sks_write_lock.remove(&ephemeral_key_id);
                    }
                }
            }
        }
        Ok(())
    }

    fn dkg_create_resharing_dealing(
        &self,
        dkg_id: IDkgId,
        threshold: NumberOfNodes,
        resharing_public_coefficients: CspPublicCoefficients,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, dkg_errors::DkgCreateReshareDealingError> {
        let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());
        let ephemeral_key_set: EphemeralKeySetBytes = {
            let key_id = dkg_id_to_key_id(&dkg_id);
            self.get_ephemeral_key(key_id)
                .map_err(dkg_errors::DkgCreateReshareDealingError::MalformedSecretKeyError)?
                .ok_or_else(|| {
                    dkg_errors::DkgCreateReshareDealingError::KeyNotFoundError(
                        dkg_errors::KeyNotFoundError {
                            internal_error: format!("No ephemeral key found for dkg {:?}", dkg_id),
                            key_id,
                        },
                    )
                })
        }?;
        let receiver_keys = &conversions::receiver_keys(receiver_keys)
            .map_err(dkg_errors::DkgCreateReshareDealingError::MalformedPublicKeyError)?;

        // TODO(CRP-50): Store the threshold public key with the private in the key
        // store.
        let reshared_threshold_secret_key: clib::types::SecretKeyBytes = {
            let key_id = public_coefficients_key_id(&resharing_public_coefficients);
            let csp_key = self.sks_read_lock().get(&key_id).ok_or_else(|| {
                dkg_errors::DkgCreateReshareDealingError::KeyNotFoundError(
                    dkg_errors::KeyNotFoundError {
                        internal_error: "Cannot find threshold secret key to reshare.".to_string(),
                        key_id,
                    },
                )
            })?;
            clib::types::SecretKeyBytes::try_from(csp_key).map_err(|_| {
                dkg_errors::DkgCreateReshareDealingError::MalformedSecretKeyError(
                    dkg_errors::MalformedSecretKeyError {
                        algorithm: AlgorithmId::ThresBls12_381,
                        internal_error: "Secret threshold key cannot be parsed as this type"
                            .to_string(),
                    },
                )
            })
        }?;

        create_resharing_dealing(
            seed,
            ephemeral_key_set.secret_key_bytes,
            dkg_id,
            threshold,
            receiver_keys,
            reshared_threshold_secret_key,
        )
        .map(CspDealing::from)
    }

    fn dkg_verify_resharing_dealing(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        csp_dealing: CspDealing,
        dealer_index: NodeIndex,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), dkg_errors::DkgVerifyReshareDealingError> {
        let receiver_keys = &conversions::receiver_keys(receiver_keys)
            .map_err(dkg_errors::DkgVerifyReshareDealingError::MalformedPublicKeyError)?;
        let dealing = conversions::dealing(&csp_dealing)
            .map_err(dkg_errors::DkgVerifyReshareDealingError::MalformedDealingError)?;
        let resharing_public_coefficients =
            PublicCoefficientsBytes::from(resharing_public_coefficients);

        verify_resharing_dealing(
            threshold,
            receiver_keys,
            dealing,
            dealer_index,
            resharing_public_coefficients,
        )
    }

    fn dkg_create_resharing_transcript(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        verified_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        verified_responses: &[Option<CspResponse>],
        dealer_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspDkgTranscript, dkg_errors::DkgCreateReshareTranscriptError> {
        let resharing_public_coefficients =
            PublicCoefficientsBytes::from(resharing_public_coefficients);
        let clib_dealings =
            conversions::dealing_map(verified_dealings).map_err(|error| match error {
                conversions::DealingMapConversionError::MalformedPublicKeyError(e) => {
                    dkg_errors::DkgCreateReshareTranscriptError::MalformedPublicKeyError(e)
                }
                conversions::DealingMapConversionError::MalformedDealingError(e) => {
                    dkg_errors::DkgCreateReshareTranscriptError::MalformedDealingError(e)
                }
            })?;
        let clib_responses: Vec<Option<CLibResponseBytes>> = {
            let clib_responses: Result<Vec<_>, _> = verified_responses
                .iter()
                .cloned()
                .map(|response_maybe| response_maybe.map(conversions::response).transpose())
                .collect();

            clib_responses
                .map_err(dkg_errors::DkgCreateReshareTranscriptError::MalformedResponseError)
        }?;
        let receiver_keys = conversions::receiver_keys(receiver_keys)
            .map_err(dkg_errors::DkgCreateReshareTranscriptError::MalformedPublicKeyError)?;
        let paired_responses: Vec<Option<CLibVerifiedResponseBytes>> =
            pair_responses_with_receivers(clib_responses, &receiver_keys)?;
        let dealer_keys = conversions::receiver_keys(dealer_keys)
            .map_err(dkg_errors::DkgCreateReshareTranscriptError::MalformedPublicKeyError)?;

        create_resharing_transcript(
            threshold,
            &clib_dealings,
            &paired_responses,
            &dealer_keys,
            &resharing_public_coefficients,
        )
        .map(CspDkgTranscript::Secp256k1)
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
    fn get_ephemeral_key(
        &self,
        key_id: KeyId,
    ) -> Result<Option<EphemeralKeySetBytes>, dkg_errors::MalformedSecretKeyError> {
        self.sks_read_lock()
            .get(&key_id)
            .map(EphemeralKeySetBytes::try_from)
            .transpose()
    }
}

/// Compute a key identifier from public coefficients
// TODO (CRP-821): Remove the duplication with key_id_from_csp_pub_coeffs
pub fn public_coefficients_key_id(csp_public_coefficients: &CspPublicCoefficients) -> KeyId {
    let mut hash = Sha256::new();
    hash.update(
        DomainSeparationContext::new("KeyId from threshold public coefficients").as_bytes(),
    );
    hash.update(
        &serde_cbor::to_vec(&csp_public_coefficients)
            .expect("Failed to serialize public coefficients"),
    );
    KeyId::from(hash.finish())
}

// The Clib API takes responses paired with the corresponding public key
fn pair_responses_with_receivers(
    clib_responses: Vec<Option<CLibResponseBytes>>,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
) -> Result<Vec<Option<CLibVerifiedResponseBytes>>, dkg_errors::DkgCreateTranscriptError> {
    if receiver_keys.len() != clib_responses.len() {
        return Err(dkg_errors::DkgCreateTranscriptError::MalformedResponseError(
                    dkg_errors::MalformedDataError{
                        algorithm: AlgorithmId::Secp256k1,
                        internal_error: format!("The response vector has a different length ({}) from the receivers vector ({}).", clib_responses.len(), receiver_keys.len()),
                        data: None}));
    }
    Ok(clib_responses
        .into_iter()
        .zip(receiver_keys.iter().copied())
        .map(|response_and_key| match response_and_key {
            (Some(response), Some((receiver_public_key, _pop))) => {
                Some(CLibVerifiedResponseBytes {
                    receiver_public_key,
                    complaints: response.complaints,
                })
            }
            (_, _) => None,
        })
        .collect())
}
