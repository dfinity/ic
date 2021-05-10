#![allow(clippy::unwrap_used)]

use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::sign::tests::{REG_V1, REG_V2};
use crate::sign::threshold_sig::ni_dkg::retain_active_keys::retain_only_active_keys;
use crate::sign::threshold_sig::ni_dkg::utils::epoch;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgUpdateFsEpochError, KeyNotFoundError,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    PublicCoefficientsBytes, Transcript,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::transcripts_to_retain::TranscriptsToRetain;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript};
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::KeyId;
use ic_types::RegistryVersion;
use std::collections::BTreeMap;

#[test]
fn should_call_csp_with_correct_parameters() {
    let transcripts = transcripts_to_retain();
    let mut csp = MockAllCryptoServiceProvider::new();
    let expected_active_keys = transcripts.public_keys();
    csp.expect_retain_threshold_keys_if_present()
        .withf(move |active_keys| *active_keys == expected_active_keys)
        .times(1)
        .return_const(());
    csp.expect_update_forward_secure_epoch()
        .withf(move |algorithm_id, epoch_| {
            *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381 && *epoch_ == epoch(REG_V1)
        })
        .times(1)
        .return_const(Ok(()));

    let result = retain_only_active_keys(&csp, transcripts);

    assert!(result.is_ok());
}

#[test]
fn should_return_error_from_csp() {
    let transcripts = transcripts_to_retain();
    let mut csp = MockAllCryptoServiceProvider::new();
    let expected_active_keys = transcripts.public_keys();
    csp.expect_retain_threshold_keys_if_present()
        .withf(move |active_keys| *active_keys == expected_active_keys)
        .times(1)
        .return_const(());
    let key_not_found_err = key_not_found_err();
    csp.expect_update_forward_secure_epoch()
        .times(1)
        .return_const(Err(
            CspDkgUpdateFsEpochError::FsKeyNotInSecretKeyStoreError(key_not_found_err.clone()),
        ));
    let result = retain_only_active_keys(&csp, transcripts);

    assert_eq!(
        result.unwrap_err(),
        DkgKeyRemovalError::FsKeyNotInSecretKeyStoreError(key_not_found_err)
    );
}

fn transcripts_to_retain() -> TranscriptsToRetain {
    let transcripts = maplit::hashset! {
        high_transcript(REG_V1),
        high_transcript(REG_V1),
        low_transcript(REG_V2),
    };
    TranscriptsToRetain::new(transcripts).unwrap()
}

fn key_not_found_err() -> KeyNotFoundError {
    KeyNotFoundError {
        internal_error: "some error".to_string(),
        key_id: KeyId::from([0; 32]),
    }
}

fn high_transcript(registry_version: RegistryVersion) -> NiDkgTranscript {
    high_transcript_with_pub_coeffs(registry_version, pub_coeffs(0))
}

fn high_transcript_with_pub_coeffs(
    registry_version: RegistryVersion,
    pub_coeffs: PublicCoefficientsBytes,
) -> NiDkgTranscript {
    let mut transcript = NiDkgTranscript::dummy_transcript_for_tests();
    transcript.dkg_id.dkg_tag = NiDkgTag::HighThreshold;
    transcript.registry_version = registry_version;
    transcript.internal_csp_transcript = csp_transcript_with_pub_coeffs(pub_coeffs);
    transcript
}

fn low_transcript(registry_version: RegistryVersion) -> NiDkgTranscript {
    low_transcript_with_pub_coeffs(registry_version, pub_coeffs(0))
}

fn low_transcript_with_pub_coeffs(
    registry_version: RegistryVersion,
    pub_coeffs: PublicCoefficientsBytes,
) -> NiDkgTranscript {
    let mut transcript = NiDkgTranscript::dummy_transcript_for_tests();
    transcript.dkg_id.dkg_tag = NiDkgTag::LowThreshold;
    transcript.registry_version = registry_version;
    transcript.internal_csp_transcript = csp_transcript_with_pub_coeffs(pub_coeffs);
    transcript
}

fn csp_transcript_with_pub_coeffs(pub_coeffs: PublicCoefficientsBytes) -> CspNiDkgTranscript {
    CspNiDkgTranscript::Groth20_Bls12_381(Transcript {
        public_coefficients: pub_coeffs,
        receiver_data: BTreeMap::new(),
    })
}

fn pub_coeffs(pub_coeffs: u8) -> PublicCoefficientsBytes {
    PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([pub_coeffs; PublicKeyBytes::SIZE])],
    }
}
